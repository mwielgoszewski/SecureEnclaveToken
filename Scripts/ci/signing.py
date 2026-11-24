#!/usr/bin/env python3
"""Install Developer ID profiles on an ephemeral GitHub macOS runner."""
import base64
from datetime import datetime, timezone
import fnmatch
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys

APP_ID = "com.mwielgoszewski.SecureEnclaveToken"
EXTENSION_ID = APP_ID + ".SecureEnclaveTokenExtension"


def validate_profile(profile, bundle_id, team):
    if profile.get("TeamIdentifier") != [team]:
        raise ValueError("Provisioning profile belongs to a different team")
    if not profile.get("ProvisionsAllDevices") or profile.get("ProvisionedDevices"):
        raise ValueError("A Developer ID distribution profile is required")
    if profile["ExpirationDate"].replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise ValueError("Provisioning profile has expired")
    entitlements = profile["Entitlements"]
    if entitlements.get("get-task-allow") or entitlements.get("com.apple.security.get-task-allow"):
        raise ValueError("Development profiles cannot be used for distribution")
    prefixes = profile["ApplicationIdentifierPrefix"]
    if len(prefixes) != 1:
        raise ValueError("Expected one application identifier prefix")
    prefix = prefixes[0]
    if not re.fullmatch(r"[A-Z0-9]{10}", prefix):
        raise ValueError("Invalid application identifier prefix")
    expected_id = prefix + "." + bundle_id
    if entitlements.get("com.apple.application-identifier", entitlements.get("application-identifier")) != expected_id:
        raise ValueError("Provisioning profile does not match the bundle identifier")
    group = prefix + "." + APP_ID
    if not any(fnmatch.fnmatchcase(group, value) for value in entitlements.get("keychain-access-groups", [])):
        raise ValueError("Provisioning profile does not authorize the shared keychain group")
    uuid = profile["UUID"]
    if not re.fullmatch(r"[A-Fa-f0-9-]{36}", uuid):
        raise ValueError("Invalid provisioning profile UUID")
    return uuid, prefix


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS":
        raise SystemExit("This helper is only for ephemeral GitHub macOS runners")
    root = Path(os.environ["RUNNER_TEMP"]) / "setoken-signing"
    if sys.argv[1:] == ["cleanup"]:
        record = root / "installed-profiles.json"
        if record.exists():
            for path in json.loads(record.read_text()):
                Path(path).unlink(missing_ok=True)
        shutil.rmtree(root, ignore_errors=True)
        return
    if sys.argv[1:] != ["prepare"]:
        raise SystemExit("Usage: signing.py prepare|cleanup")
    team = os.environ["APPLE_TEAM_ID"]
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise ValueError("Set APPLE_TEAM_ID to your ten-character team ID")
    root.mkdir(mode=0o700, exist_ok=False)
    os.umask(0o077)
    for variable, filename in [("DEVELOPER_ID_P12_BASE64", "certificate.p12"),
                               ("NOTARY_API_KEY_BASE64", "notary.p8")]:
        data = base64.b64decode("".join(os.environ[variable].split()), validate=True)
        if not data:
            raise ValueError("Empty signing credential")
        (root / filename).write_bytes(data)
    profiles_dir = Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    installed = []
    mapping = {}
    prefixes = set()
    with open(os.environ["GITHUB_ENV"], "a") as env:
        for secret, setting, bundle_id in [
            ("APP_PROFILE_BASE64", "SETOKEN_APP_PROFILE", APP_ID),
            ("EXTENSION_PROFILE_BASE64", "SETOKEN_EXTENSION_PROFILE", EXTENSION_ID),
        ]:
            data = base64.b64decode("".join(os.environ[secret].split()), validate=True)
            source = root / (setting + ".provisionprofile")
            source.write_bytes(data)
            decoded = subprocess.check_output(["security", "cms", "-D", "-i", str(source)])
            uuid, prefix = validate_profile(plistlib.loads(decoded), bundle_id, team)
            prefixes.add(prefix)
            destination = profiles_dir / (uuid + ".provisionprofile")
            # Do not replace profiles owned by another workflow or local setup.
            with destination.open("xb") as output:
                output.write(data)
            installed.append(str(destination))
            (root / "installed-profiles.json").write_text(json.dumps(installed))
            env.write(setting + "=" + uuid + "\n")
            mapping[bundle_id] = uuid
        if len(prefixes) != 1:
            raise ValueError("App and extension must share the same application identifier prefix")
        env.write("SETOKEN_KEYCHAIN_GROUP=" + prefixes.pop() + "." + APP_ID + "\n")
    options = {"method": "developer-id", "destination": "export", "teamID": team,
               "signingStyle": "manual", "signingCertificate": "Developer ID Application",
               "provisioningProfiles": mapping, "manageAppVersionAndBuildNumber": False}
    with (root / "ExportOptions.plist").open("wb") as output:
        plistlib.dump(options, output)
    print("Prepared Developer ID profiles and export options.")


if __name__ == "__main__":
    main()
