"""A negative index check selects reference data; literal credential data stays refused."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('predicate_guard_under_test', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PredicateGuardTests(unittest.TestCase):
    def test_negative_index_selects_existing_source(self):
        source = 'password' + ' = "" if separator < 0 else userinfo[separator + 1 :]\n'
        GUARD.require_safe_source('file source', 'uri_reader.py', source)

    def test_condition_and_branch_data_stay_refused(self):
        value = 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'
        expressions = (
            repr(value) + ' if separator < 0 else userinfo',
            'userinfo if separator < ' + repr(value) + ' else None',
            '32 if separator < 0 else userinfo',
            'userinfo if separator < 32 else None',
            'userinfo if factory(' + repr(value) + ') < 0 else None',
            'userinfo if separator < 0 else (' + repr(value[:8]) + ' + ' + repr(value[8:]) + ')',
        )
        for index, expression in enumerate(expressions):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'uri_reader.py', 'password' + ' = ' + expression)


if __name__ == '__main__':
    unittest.main()
