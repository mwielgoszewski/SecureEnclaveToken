#!/usr/bin/env python3
"""Sign a downloaded CI app locally; never execute code from the artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys

from ci.signing import APP_ID, EXTENSION_ID, validate_profile

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = Path('Contents/PlugIns/SecureEnclaveTokenExtension.appex')
BINARIES = {
    Path('Contents/MacOS/SecureEnclaveToken'),
    EXTENSION / 'Contents/MacOS/SecureEnclaveTokenExtension',
}
MACHO = {bytes.fromhex(s) for s in (
    'feedface', 'cefaedfe', 'feedfacf', 'cffaedfe',
    'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca',
)}


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True)


def inspect_app(app):
    """Accept this project's current two-executable layout, without launching it."""
    if app.is_symlink() or not app.is_dir() or app.name != 'SecureEnclaveToken.app':
        raise ValueError('Expected an extracted SecureEnclaveToken.app directory')
    found = set()
    for path in app.rglob('*'):
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f'Unsupported symlink or special file: {path}')
        relative = path.relative_to(app)
        if path.is_dir():
            if path.suffix in {'.app', '.appex', '.framework', '.xpc'} and relative != EXTENSION:
                raise ValueError(f'Unexpected nested code bundle: {relative}')
            continue
        with path.open('rb') as stream:
            if stream.read(4) in MACHO:
                found.add(relative)
        if path.name == 'Info.plist' and relative not in {
            Path('Contents/Info.plist'), EXTENSION / 'Contents/Info.plist',
        }:
            if plistlib.loads(path.read_bytes()).get('CFBundleExecutable'):
                raise ValueError(f'Unexpected executable resource bundle: {relative}')
    if found != BINARIES:
        raise ValueError(f'Unexpected Mach-O layout: {sorted(str(p) for p in found)}')
    for bundle, identifier, executable in (
        (app, APP_ID, 'SecureEnclaveToken'),
        (app / EXTENSION, EXTENSION_ID, 'SecureEnclaveTokenExtension'),
    ):
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if info.get('CFBundleIdentifier') != identifier or info.get('CFBundleExecutable') != executable:
            raise ValueError(f'Unexpected bundle identity: {bundle}')
        if info.get('LSMinimumSystemVersion') != '26.0':
            raise ValueError(f'Unexpected deployment target: {bundle}')
        if run('/usr/bin/lipo', '-archs', bundle / 'Contents/MacOS' / executable).stdout.strip() != b'arm64':
            raise ValueError(f'Expected an ARM64 executable: {bundle}')


def check_identity(identity, team):
    if not re.fullmatch(r'[A-Fa-f0-9]{40}', identity):
        raise ValueError('Use the 40-character identity hash from security find-identity -v -p codesigning')
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('Expected a ten-character Apple team ID')
    identities = run('/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning').stdout.decode()
    pattern = rf'\b{identity}\s+"Developer ID Application: [^"\n]+\({team}\)"'
    if not re.search(pattern, identities, re.IGNORECASE):
        raise ValueError('No matching valid Developer ID Application identity in the local Keychain')


def profile_entitlements(profile, bundle_id, team, identity):
    _, prefix = validate_profile(profile, bundle_id, team)
    certificates = {hashlib.sha1(cert).hexdigest().upper()
                    for cert in profile.get('DeveloperCertificates', [])}
    if identity.upper() not in certificates:
        raise ValueError(
            'Provisioning profile does not authorize the selected signing certificate. '
            f'Selected: {identity.upper()}; authorized: {", ".join(sorted(certificates)) or "none"}. '
            'Regenerate the Developer ID profile with the selected certificate.')
    authorized = profile['Entitlements']
    if authorized.get('com.apple.developer.team-identifier', team) != team:
        raise ValueError('Provisioning profile entitlement has a different team')
    target = 'SecureEnclaveToken' if bundle_id == APP_ID else 'SecureEnclaveTokenExtension'
    template = (ROOT / target / (target + '.entitlements')).read_text()
    entitlements = plistlib.loads(template.replace('$(AppIdentifierPrefix)', prefix + '.').encode())
    entitlements['com.apple.application-identifier'] = prefix + '.' + bundle_id
    entitlements['com.apple.developer.team-identifier'] = team
    if entitlements.get('keychain-access-groups') != [prefix + '.' + APP_ID]:
        raise ValueError('Local entitlements must use the expected shared keychain group')
    if entitlements.get('get-task-allow') or entitlements.get('com.apple.security.get-task-allow'):
        raise ValueError('Debugger entitlements are not permitted for distribution')
    return prefix, entitlements


def verify(bundle, expected, team):
    run('/usr/bin/codesign', '--verify', '--strict', '--verbose=2', bundle)
    details = run('/usr/bin/codesign', '-dv', '--verbose=4', bundle).stderr.decode()
    if (f'TeamIdentifier={team}\n' not in details
            or 'Authority=Developer ID Application:' not in details
            or not re.search(r'flags=.*\bruntime\b', details)
            or 'Timestamp=' not in details):
        raise ValueError(f'Missing distribution signature, runtime, or timestamp: {bundle}')
    actual = plistlib.loads(run('/usr/bin/codesign', '-d', '--entitlements', ':-', bundle).stdout)
    if actual != expected:
        raise ValueError(f'Signed entitlements do not match the approved entitlements: {bundle}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, type=Path, help='Extracted unsigned app; left untouched')
    parser.add_argument('--check', action='store_true', help='Inspect bundle layout only; no credentials or signing')
    parser.add_argument('--identity', help='Developer ID Application identity SHA-1 from security find-identity')
    parser.add_argument('--team', help='Existing Apple signing team ID')
    parser.add_argument('--app-profile', type=Path, help='Local app Developer ID .provisionprofile')
    parser.add_argument('--extension-profile', type=Path, help='Local extension Developer ID .provisionprofile')
    parser.add_argument('--notary-profile', help='Existing notarytool Keychain profile name')
    parser.add_argument('--notary-keychain', type=Path,
                        default=Path.home() / 'Library/Keychains/login.keychain-db',
                        help='Local Keychain containing notarization credentials (default: login)')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/local-release', help='New output directory')
    args = parser.parse_args()
    # Inspect before resolving so a symlink supplied as the app is rejected too.
    inspect_app(args.app)
    source = args.app.resolve()
    for binary in sorted(BINARIES):
        print(f'{hashlib.sha256((source / binary).read_bytes()).hexdigest()}  {binary}', flush=True)
    if args.check:
        print('Bundle layout OK. This does not verify provenance or the behavior of the binaries.')
        return
    required = ('identity', 'team', 'app_profile', 'extension_profile', 'notary_profile')
    if missing := [name.replace('_', '-') for name in required if not getattr(args, name)]:
        parser.error('Signing requires: ' + ', '.join('--' + name for name in missing))
    check_identity(args.identity, args.team)
    profiles = []
    for path, bundle_id in ((args.app_profile, APP_ID), (args.extension_profile, EXTENSION_ID)):
        data = path.read_bytes()
        decoded = plistlib.loads(run('/usr/bin/security', 'cms', '-D', '-i', path).stdout)
        try:
            prefix, entitlements = profile_entitlements(decoded, bundle_id, args.team, args.identity)
        except ValueError as error:
            raise ValueError(f'{path}: {error}') from error
        profiles.append((data, prefix, entitlements))
    if profiles[0][1] != profiles[1][1]:
        raise ValueError('Both provisioning profiles must use the same App ID prefix')
    output = args.output.resolve()
    if output == source or source in output.parents:
        raise ValueError('Output must be outside the downloaded app')
    # Fail on reuse; never overwrite an earlier release or modify the download.
    output.mkdir(parents=True, exist_ok=False)
    app = output / 'SecureEnclaveToken.app'
    shutil.copytree(source, app)
    inspect_app(app)
    bundles = (app, app / EXTENSION)
    for index in (1, 0):  # Sign the embedded extension before the containing app.
        bundle = bundles[index]
        data, _, entitlements = profiles[index]
        (bundle / 'Contents/embedded.provisionprofile').write_bytes(data)
        entitlement_path = output / ('extension-entitlements.plist' if index else 'app-entitlements.plist')
        entitlement_path.write_bytes(plistlib.dumps(entitlements))
        print(f'Signing {bundle.name} with the local Keychain identity…', flush=True)
        run('/usr/bin/codesign', '--force', '--sign', args.identity, '--options', 'runtime',
            '--timestamp', '--generate-entitlement-der', '--entitlements', entitlement_path, bundle)
        verify(bundle, entitlements, args.team)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', app)
    submission = output / 'notarization.zip'
    run('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, submission)
    print('Submitting to Apple; credentials stay in the local Keychain…', flush=True)
    notary_auth = ['--keychain-profile', args.notary_profile, '--keychain', str(args.notary_keychain)]
    # Persist the submission response even on timeout so it can be queried later.
    with (output / 'notarization.json').open('wb') as log:
        result = subprocess.run(['/usr/bin/xcrun', 'notarytool', 'submit', str(submission),
                                 *notary_auth, '--wait', '--timeout', '30m',
                                 '--output-format', 'json'], stdout=log)
    try:
        response = json.loads((output / 'notarization.json').read_bytes())
    except ValueError as error:
        raise ValueError(f'No notarization response; inspect {output}/notarization.json and the error above.') from error
    if submission_id := response.get('id'):
        print(f'Notarization submission: {submission_id}', flush=True)
        subprocess.run(['/usr/bin/xcrun', 'notarytool', 'log', submission_id,
                        *notary_auth, str(output / 'notarization-log.json')],
                       check=False)
    if result.returncode != 0 or response.get('status') != 'Accepted':
        raise ValueError(f'Notarization not accepted. Inspect {output}/notarization*.json before retrying.')
    run('/usr/bin/xcrun', 'stapler', 'staple', app)
    run('/usr/bin/xcrun', 'stapler', 'validate', app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', app)
    run('/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', app)
    archive = output / 'SecureEnclaveToken-signed-arm64.zip'
    run('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n')
    print(f'Ready: {archive}\nSHA-256: {digest}')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print((error.stderr or b'').decode(errors='replace'), file=sys.stderr)
        sys.exit(f'Command failed ({error.returncode}): {error.cmd[0]}')
    except (ValueError, OSError, KeyError, plistlib.InvalidFileException) as error:
        sys.exit(str(error))
