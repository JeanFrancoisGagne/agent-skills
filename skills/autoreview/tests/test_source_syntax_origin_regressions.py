"""Branch syntax and existing placeholder operands keep their source roles."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("source_syntax_guard", ROOT / "scripts/autoreview_source_guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def opaque():
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"


class SourceSyntaxOriginTests(unittest.TestCase):
    def check(self, path, source, refused=False):
        if refused:
            with self.assertRaises(SystemExit):
                GUARD.require_safe_source("file source", path, source)
        else:
            GUARD.require_safe_source("file source", path, source)

    def test_original_swift_switch_status_fixture(self):
        self.check("status.swift", (ROOT / "tests/fixtures/swift-benign-status-literals.swift").read_text())

    def test_swift_case_tuple_return_is_not_a_credential_call(self):
        self.check("status.swift", 'case "ok-empty", "ok-token":\n    return ("Heartbeat ok", .green)\n')

    def test_switch_label_has_the_same_role_in_javascript(self):
        self.check("status.js", 'function show(status) {\n switch (status) {\n case "ok-token": return ("Heartbeat ok", "green");\n }\n}\n')

    def test_case_body_assignments_keep_literal_checks(self):
        for suffix in ('token = ' + json.dumps(opaque()), 'password = ' + json.dumps(opaque())):
            with self.subTest(field=suffix.split('=')[0]):
                self.check("status.swift", 'case "ok-token":\n    ' + suffix + '\n', refused=True)

    def test_case_body_keeps_raw_credential_marker_checks(self):
        source = 'case "ok-token":\n return "' + 'sk-' + opaque() + '"\n'
        self.check("status.swift", source, refused=True)

    def test_case_text_inside_a_string_keeps_its_denial(self):
        source = 'let note = """\ncase "ok-token":\n return ("Heartbeat ok", .green)\n"""\n'
        self.check("status.swift", source, refused=True)

    def test_object_and_scalar_credential_values_are_not_case_labels(self):
        for source in ('token = ' + json.dumps(opaque()), '{"token": ' + json.dumps(opaque()) + '}'):
            self.check("status.swift", source, refused=True)

    def test_existing_placeholder_in_qualified_environment_fallback(self):
        self.check("runtime.py", 'import os\npassword = os.getenv("PASSWORD") or "redacted"\n')

    def test_existing_placeholder_boolean_operands_keep_their_literal_role(self):
        for operator in ('or', 'and'):
            self.check("runtime.py", 'password = source ' + operator + ' "redacted"\n')

    def test_placeholder_neighbors_keep_their_literal_checks(self):
        literal = json.dumps(opaque())
        for expression in ('source or ' + literal, 'source or ("redacted" + ' + literal + ')',
                           'source or ["redacted"]', 'source or build("redacted")',
                           'source or "redacted" or ' + literal):
            with self.subTest(case=expression.split()[0]):
                self.check("runtime.py", 'password = ' + expression + '\n', refused=True)

    def test_unproved_bare_lookup_keeps_its_denial(self):
        self.check("runtime.py", 'password = getenv("PASSWORD") or "redacted"\n', refused=True)

    def test_unproved_pem_body_keeps_its_denial(self):
        source = 'const privateKey = "-----BEGIN ' + 'PRIVATE KEY-----\\n" + unknownBody + "\\n-----END ' + 'PRIVATE KEY-----";\n'
        self.check("runtime.ts", source, refused=True)


if __name__ == "__main__":
    unittest.main()
