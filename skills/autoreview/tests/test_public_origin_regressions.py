"""Exercise retained public CLI fixtures at the source classification boundary."""
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = load_module("public_origin_guard", ROOT / "scripts/autoreview_source_guard.py")
PUBLIC = load_module("retained_public_cases", ROOT / "tests/test_autoreview_source_guard.py")


def retained_cases(method):
    cases = []

    class Capture(PUBLIC.AutoreviewSourceGuardPublicTests):
        def assert_source_reference_public_cli(
            self, relative, content, *, refused, phase="dataset",
        ):
            cases.append((relative, content, refused))

    getattr(Capture(method), method)()
    return cases


class PublicOriginRegressionTests(unittest.TestCase):
    def check_retained_cases(self, method):
        for index, (relative, content, refused) in enumerate(retained_cases(method)):
            with self.subTest(case=index, path=relative):
                if refused:
                    with self.assertRaises(SystemExit):
                        GUARD.require_safe_source("file source", relative, content)
                else:
                    GUARD.require_safe_source("file source", relative, content)

    def test_placeholder_field_identity(self):
        self.check_retained_cases("test_public_cli_keeps_mismatched_placeholder_fields_refused")

    def test_unproved_origin(self):
        self.check_retained_cases("test_public_cli_keeps_unproved_credential_origins_refused")

    def test_computed_auth_scopes(self):
        self.check_retained_cases("test_computed_auth_reference_keeps_function_scopes_public_cli")

    def test_destructured_callable(self):
        self.check_retained_cases("test_destructured_reference_public_cli")

    def test_entropy_and_callback_origins(self):
        self.check_retained_cases("test_imported_entropy_and_callback_origins_public_cli")

    def test_scope_mutation_refusals(self):
        self.check_retained_cases("test_scoped_auth_origins_keep_credential_refusals_public_cli")

    def test_destructured_literal_refusals(self):
        self.check_retained_cases("test_destructured_reference_refusals_public_cli")

    def test_factory_namespace_and_writes_stay_refused(self):
        source = retained_cases("test_destructured_reference_public_cli")[0][1]
        literal = json.dumps(PUBLIC.realistic_secret_value())
        sources = (
            source.replace('from "vitest"', 'from "other-package"'),
            source.replace('vi.mock(', 'unknown('),
            source + 'const alias = vi; alias.mock = replacement;\n',
            source.replace('oauthResolveMock: vi.fn()', 'oauthResolveMock: () => ' + literal),
            source + 'oauthResolveMock.payload = ' + literal + ';\n',
            source.replace('const {', 'function shadow(vi) { const {', 1) + '}\n',
        )
        for index, content in enumerate(sources):
            with self.subTest(case=index), self.assertRaises(SystemExit):
                GUARD.require_safe_source("file source", "entry.ts", content)

    def test_runtime_alias_writes_and_call_literals_stay_refused(self):
        source = retained_cases("test_computed_auth_reference_keeps_function_scopes_public_cli")[0][1]
        literal = json.dumps(PUBLIC.realistic_secret_value())
        sources = (
            source.replace('requestAuth = await', 'registry.lookup = () => ' + literal + '; requestAuth = await'),
            source.replace('registry.lookup(model)', 'registry.lookup(model, ' + literal + ')'),
            source.replace('requestAuth = await', 'function mutate(value) { value.lookup = () => ' + literal + '; } mutate(registry); requestAuth = await'),
        )
        for index, content in enumerate(sources):
            with self.subTest(case=index), self.assertRaises(SystemExit):
                GUARD.require_safe_source("file source", "entry.ts", content)


if __name__ == "__main__":
    unittest.main()
