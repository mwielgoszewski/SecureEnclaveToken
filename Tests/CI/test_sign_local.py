"""Check local signing boundaries without using private keys or Apple's service."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Scripts'))
spec = importlib.util.spec_from_file_location('sign_local', ROOT / 'Scripts/sign-local.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class LocalSigningTests(unittest.TestCase):
    def setUp(self):
        self.team = 'ABCDEFGHIJ'
        self.prefix = 'ZYXWVUTSRQ'  # App ID prefixes may differ from team IDs.
        self.certificate = b'fake DER certificate for unit tests'
        self.identity = hashlib.sha1(self.certificate).hexdigest().upper()
        self.profile = {
            'TeamIdentifier': [self.team],
            'ApplicationIdentifierPrefix': [self.prefix],
            'ProvisionsAllDevices': True,
            'ExpirationDate': datetime.now(timezone.utc) + timedelta(days=1),
            'UUID': '12345678-1234-1234-1234-123456789ABC',
            'DeveloperCertificates': [self.certificate],
            'Entitlements': {
                'com.apple.application-identifier': self.prefix + '.' + signing.APP_ID,
                'com.apple.developer.team-identifier': self.team,
                'keychain-access-groups': [self.prefix + '.*'],
                'unrequested-profile-permission': True,
            },
        }

    def test_entitlements_use_profile_prefix_and_separate_target_permissions(self):
        for bundle_id in (signing.APP_ID, signing.EXTENSION_ID):
            self.profile['Entitlements']['com.apple.application-identifier'] = self.prefix + '.' + bundle_id
            prefix, entitlements = signing.profile_entitlements(
                self.profile, bundle_id, self.team, self.identity)
            self.assertEqual(prefix, self.prefix)
            self.assertEqual(entitlements['keychain-access-groups'], [self.prefix + '.' + signing.APP_ID])
            self.assertEqual(entitlements['com.apple.application-identifier'], self.prefix + '.' + bundle_id)
            self.assertEqual(entitlements['com.apple.developer.team-identifier'], self.team)
            self.assertTrue(entitlements['com.apple.security.app-sandbox'])
            self.assertEqual(entitlements.get('com.apple.security.smartcard', False),
                             bundle_id == signing.EXTENSION_ID)
            self.assertNotIn('unrequested-profile-permission', entitlements)
            self.assertNotIn('$(', plistlib.dumps(entitlements).decode())

    def test_wrong_certificate_or_team_entitlement_rejected(self):
        for changes in ({'DeveloperCertificates': [b'other certificate']},
                        {'DeveloperCertificates': []},
                        {'Entitlements': dict(self.profile['Entitlements'],
                                              **{'com.apple.developer.team-identifier': 'OTHERTEAM1'})}):
            profile = copy.deepcopy(self.profile)
            profile.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                signing.profile_entitlements(profile, signing.APP_ID, self.team, self.identity)

    def test_development_identity_rejected(self):
        for kind in ('Apple Development', 'Developer ID Installer', 'Developer ID Application'):
            identities = f'  1) {self.identity} "{kind}: Test ({self.team})"\n'.encode()
            with patch.object(signing, 'run', return_value=subprocess.CompletedProcess([], 0, identities)):
                if kind == 'Developer ID Application':
                    signing.check_identity(self.identity, self.team)
                else:
                    with self.assertRaises(ValueError):
                        signing.check_identity(self.identity, self.team)

    def make_app(self, parent):
        app = parent / 'SecureEnclaveToken.app'
        for relative in signing.BINARIES:
            binary = app / relative
            binary.parent.mkdir(parents=True)
            binary.write_bytes(bytes.fromhex('cffaedfe') + b'fixture')
            info = {
                'CFBundleIdentifier': signing.APP_ID if binary.name == 'SecureEnclaveToken' else signing.EXTENSION_ID,
                'CFBundleExecutable': binary.name,
                'LSMinimumSystemVersion': '26.0',
            }
            (binary.parent.parent / 'Info.plist').write_bytes(plistlib.dumps(info))
        return app

    def test_layout_rejects_extra_code_symlinks_and_wrong_identity(self):
        for mutation in ('none', 'macho', 'symlink', 'bundle-id', 'executable-resource'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                app = self.make_app(Path(directory))
                if mutation == 'macho':
                    (app / 'Contents/extra.dylib').write_bytes(bytes.fromhex('cffaedfe'))
                elif mutation == 'symlink':
                    (app / 'Contents/external').symlink_to('/tmp')
                elif mutation == 'bundle-id':
                    info = app / 'Contents/Info.plist'
                    data = plistlib.loads(info.read_bytes())
                    data['CFBundleIdentifier'] = 'other.app'
                    info.write_bytes(plistlib.dumps(data))
                elif mutation == 'executable-resource':
                    resource = app / 'Contents/Resources/extra.bundle/Contents'
                    resource.mkdir(parents=True)
                    (resource / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'run'}))
                with patch.object(signing, 'run', return_value=subprocess.CompletedProcess([], 0, b'arm64\n')):
                    if mutation == 'none':
                        signing.inspect_app(app)
                    else:
                        with self.assertRaises(ValueError):
                            signing.inspect_app(app)


if __name__ == '__main__':
    unittest.main()
