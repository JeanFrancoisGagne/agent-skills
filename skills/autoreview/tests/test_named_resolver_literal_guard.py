"""A resolver spelling cannot exempt literal credential data."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('resolver_guard_under_test', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class ResolverLiteralGuardTests(unittest.TestCase):
    def test_unproved_resolver_keeps_literal_refusal(self):
        sample_value = ('A7f9K2m4Q8v6' + 'N3x5R1p0T9z8').upper()
        call = 'password' + ' = resolve_secret(' + repr(sample_value) + ')\n'
        sources = (
            call,
            'def resolve_secret(name): return name\n' + call,
            'from other_package import resolve_secret\n' + call,
            'from core.secrets import resolve_secret\nresolve_secret = replacement\n' + call,
            'from core.secrets import resolve_secret\nresolve_secret.__code__ = replacement\n' + call,
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'consumer.py', source)


if __name__ == '__main__':
    unittest.main()
