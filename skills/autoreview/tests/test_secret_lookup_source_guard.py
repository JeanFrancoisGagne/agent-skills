"""Secret lookup selectors and boolean options carry no credential data."""
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('lookup_guard_under_test', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class SecretLookupGuardTests(unittest.TestCase):
    def check_source(self, expression):
        GUARD.require_safe_source('file source', 'consumer.py', 'from core.secrets import resolve_secret\napi_key = ' + expression)

    def test_named_selector_and_boolean_lookup_options(self):
        expressions = (
            'resolve_secret("SERVICE_API_KEY")',
            'resolve_secret("SERVICE_API_KEY", required=False)',
            'resolve_secret("SERVICE_API_KEY", required=True, audit=False)',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.check_source(expression)

    def test_secret_data_and_unknown_arguments_stay_refused(self):
        expressions = (
            'resolve_secret(123, required=False)',
            'resolve_secret("opaque-private-value")',
            'resolve_secret("SERVICE_API_KEY", default="opaque-private-value")',
            'resolve_secret("SERVICE_API_KEY", required="opaque-private-value")',
            'resolve_secret("SERVICE_API_KEY", required=0)',
            'resolve_secret("SERVICE_API_KEY", False)',
            'other_call("SERVICE_API_KEY", required=False)',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                with self.assertRaises(SystemExit):
                    self.check_source(expression)

    def test_decoded_credential_values_stay_refused(self):
        sample_value = 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'
        expressions = (
            'resolve_secret(' + repr(sample_value) + ', required=False)',
            'resolve_secret("postgres://user:" + ' + repr(sample_value) + ' + "@host/db")',
            'resolve_secret("SERVICE_API_KEY", audit=[' + repr(sample_value) + '])',
        )
        for expression in expressions:
            with self.subTest(shape=expression.split('(', 1)[0]):
                with self.assertRaises(SystemExit):
                    self.check_source(expression)

    def test_local_identity_resolver_cannot_exempt_literal_data(self):
        sample_value = ('A7f9K2m4Q8v6' + 'N3x5R1p0T9z8').upper()
        source = 'def resolve_secret(name): return name\n' + 'password' + ' = resolve_secret(' + repr(sample_value) + ')\n'
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', 'consumer.py', source)

    def test_opaque_uppercase_is_not_a_selector(self):
        sample_value = ('A7f9K2m4Q8v6' + 'N3x5R1p0T9z8').upper()
        for index, value in enumerate((sample_value, "SERVICE_" + sample_value + "_KEY")):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    self.check_source('resolve_secret(' + repr(value) + ')')

    def test_imported_binding_must_stay_unshadowed(self):
        sample_value = ('A7f9K2m4Q8v6' + 'N3x5R1p0T9z8').upper()
        call = 'password' + ' = resolve_secret(' + repr(sample_value) + ')\n'
        sources = (
            call,
            'def resolve_secret(name): return name\n' + call,
            'from other_package import resolve_secret\n' + call,
            'from core.secrets import resolve_secret, arbitrary as resolve_secret\n' + call,
            'from core.secrets import resolve_secret\nresolve_secret = replacement\n' + call,
            'from core.secrets import resolve_secret\nresolve_secret.__code__ = replacement\n' + call,
            'from core.secrets import resolve_secret\nsetattr(resolve_secret, "__code__", replacement)\n' + call,
            'from core.secrets import resolve_secret\nvars()[\"resolve_secret\"] = replacement\n' + call,
            'from core.secrets import resolve_secret\nsys.modules[\"core.secrets\"] = replacement\n' + call,
            'def unrelated():\n    from core.secrets import resolve_secret\n' + call,
            'from core.secrets import resolve_secret\ndef f(resolve_secret):\n    ' + call,
            'from core.secrets import resolve_secret\n' + call.replace('resolve_secret(', 'vault.resolve_secret('),
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'consumer.py', source)


if __name__ == '__main__':
    unittest.main()
