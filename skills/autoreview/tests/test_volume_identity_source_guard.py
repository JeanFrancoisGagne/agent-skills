"""Paired null volume identities stay reviewable without exempting credentials."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('volume_guard_under_test', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def volume_fixture(prefix='case-'):
    return "volume = {" + repr('token') + ": '0' * 32, " + repr('volume_name') + ": " + repr(prefix) + " + '0' * 32}\n"


class VolumeIdentityGuardTests(unittest.TestCase):
    def test_paired_null_volume_identity(self):
        sources = (
            volume_fixture('sam-t13-'),
            "volume = {\n  " + repr('volume_name') + ": 'case-' + (32 * '0'),\n  " + repr('token') + ": 32 * '0',\n}\n",
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                GUARD.require_safe_source('file source', 'owner.py', source)

    def test_unpaired_or_changed_identity_stays_refused(self):
        field_name = repr('token')
        name = repr('volume_name')
        base = volume_fixture()
        sources = (
            'token' + " = '0' * 32\n",
            'auth = {' + field_name + ": '0' * 32}\n",
            base.replace(name, repr('account_name')),
            base.replace("'0' * 32", "'0' * 31", 1),
            base.replace("'0' * 32", "'1' * 32"),
            base.replace("'0' * 32", "bytes([0] * 32)", 1),
            base.replace("'0' * 32", "'0' * 32 + credential_value", 1),
            base.replace("'0' * 32", "'0' * 32 + 'suffix'", 1),
            base.replace('}', ', ' + field_name + ": opaque_value}"),
            base.replace('}', ', **extra_fields}'),
            base.replace("'case-'", "credential_prefix"),
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'owner.py', source)

    def test_genuine_credential_beside_fixture_stays_refused(self):
        sample_value = 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'
        sources = (
            volume_fixture() + 'password' + ' = ' + repr(sample_value),
            volume_fixture().replace("'0' * 32", repr(sample_value), 1),
            volume_fixture().replace("'case-'", repr(sample_value)),
            volume_fixture() + 'token' + " = 'fixture-token' + " + repr(sample_value),
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'owner.py', source)


if __name__ == '__main__':
    unittest.main()
