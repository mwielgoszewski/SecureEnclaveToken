"""Exercise distribution-profile rejection without accessing a keychain."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / 'Scripts/ci/signing.py'
spec = importlib.util.spec_from_file_location('signing', path)
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.team = 'ABCDEFGHIJ'
        self.profile = {
            'TeamIdentifier': [self.team],
            'ApplicationIdentifierPrefix': [self.team],
            'ProvisionsAllDevices': True,
            'ExpirationDate': datetime.now(timezone.utc) + timedelta(days=1),
            'UUID': '12345678-1234-1234-1234-123456789ABC',
            'Entitlements': {
                'com.apple.application-identifier': self.team + '.' + signing.APP_ID,
                'keychain-access-groups': [self.team + '.*'],
            },
        }

    def test_distribution_profile(self):
        self.assertEqual(signing.validate_profile(self.profile, signing.APP_ID, self.team),
                         (self.profile['UUID'], self.team))

    def test_extension_can_share_app_group(self):
        p = self.profile
        p['Entitlements']['com.apple.application-identifier'] = self.team + '.' + signing.EXTENSION_ID
        p['Entitlements']['keychain-access-groups'] = [self.team + '.' + signing.APP_ID]
        signing.validate_profile(p, signing.EXTENSION_ID, self.team)

    def test_reject_wrong_or_unusable_profiles(self):
        changes = [
            {'TeamIdentifier': ['OTHERTEAM1']},
            {'ProvisionsAllDevices': False},
            {'ProvisionedDevices': ['some-device']},
            {'ExpirationDate': datetime.now(timezone.utc) - timedelta(days=1)},
            {'ApplicationIdentifierPrefix': []},
            {'UUID': '../../outside-the-profile-directory'},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                p = copy.deepcopy(self.profile)
                p.update(change)
                signing.validate_profile(p, signing.APP_ID, self.team)

    def test_reject_wrong_entitlements(self):
        changes = [
            {'com.apple.application-identifier': self.team + '.other.app'},
            {'keychain-access-groups': ['OTHERTEAM1.*']},
            {'keychain-access-groups': []},
            {'get-task-allow': True},
            {'com.apple.security.get-task-allow': True},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                p = copy.deepcopy(self.profile)
                p['Entitlements'].update(change)
                signing.validate_profile(p, signing.APP_ID, self.team)


if __name__ == '__main__':
    unittest.main()
