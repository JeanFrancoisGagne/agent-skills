"""Source-path predicates and separators retain their bounded argument roles."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autoreview_source_guard.py"
SPEC = importlib.util.spec_from_file_location("source_metadata_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def opaque():
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"


class PythonSourceMetadataGuardTests(unittest.TestCase):
    def check_source(self, source, refused=False):
        if refused:
            with self.assertRaises(SystemExit):
                GUARD.require_safe_source("file source", "metadata.py", source)
        else:
            GUARD.require_safe_source("file source", "metadata.py", source)

    def test_actual_source_guard_context_setup(self):
        source = SCRIPT.read_text(encoding="utf-8")
        node = next(part for part in ast.parse(source).body
                    if isinstance(part, ast.FunctionDef) and part.name == "require_safe_source")
        self.check_source("from pathlib import Path\n" + ast.get_source_segment(source, node) + "\n")

    def test_complete_current_guard_source_passes_native_preflight(self):
        GUARD.require_safe_source("file source", "skills/autoreview/scripts/autoreview_source_guard.py",
                                  SCRIPT.read_text(encoding="utf-8"))

    def test_source_suffix_predicate_is_public_metadata(self):
        for suffix in (".py", ".json", ".go"):
            with self.subTest(suffix=suffix):
                self.check_source("from pathlib import Path\n" + "token" +
                                  " = store.set(select(text) if Path(rel).suffix == " +
                                  repr(suffix) + " else None)\n")

    def test_path_separator_normalization_is_public_metadata(self):
        self.check_source("source_" + "token" + " = store.set(rel.replace('\\\\', '/'))\n")

    def test_unrelated_control_headers_do_not_rescan_the_complete_source(self):
        source = "".join("if condition_" + str(index) + ":\n    pass\n" for index in range(64))
        with patch.object(GUARD, "string_contexts_at", wraps=GUARD.string_contexts_at) as contexts:
            self.assertEqual(GUARD.python_control_reference_ranges(source), ())
        self.assertEqual(contexts.call_count, 0)

    def test_sensitive_control_headers_keep_context_and_body_checks(self):
        for source in ("if token:\n    pass\n", '"""\nif token:\n    pass\n"""\n'):
            with self.subTest(source=source):
                with patch.object(GUARD, "string_contexts_at", wraps=GUARD.string_contexts_at) as contexts:
                    ranges = GUARD.python_control_reference_ranges(source)
                self.assertEqual(contexts.call_count, 1)
                self.assertEqual(bool(ranges), not source.startswith('"""'))
        self.check_source("if token:\n    password = " + json.dumps(opaque()) + "\n", refused=True)

    def test_other_literals_and_suffixes_stay_refused(self):
        value = json.dumps(opaque())
        sources = (
            "token = store.set(rel.replace('\\\\', '/')) + " + value,
            "token = store.set(" + value + ".replace('\\\\', '/'))",
            "token = store.set(rel.replace(" + value + ", '/'))",
            "token = store.set(rel.replace('\\\\', " + value + "))",
            "token = store.set(rel.replace('\\\\', '/', 1))",
            "token = store.set(rel.other('\\\\', '/'))",
            "token = store.set(select(text) if Path(rel).suffix == " + value + " else None)",
            "token = store.set(select(text) if Path(rel).suffix == '.py' + " + value + " else None)",
            "token = store.set(select(text) if Path(" + value + ").suffix == '.py' else None)",
            "token = store.set(" + value + " if Path(rel).suffix == '.py' else None)",
            "token = store.set(select(text) if Path(rel).other == '.py' else None)",
            "token = store.set(select(text) if Path(rel).suffix != '.py' else None)",
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index):
                self.check_source("from pathlib import Path\n" + source + "\n", refused=True)


if __name__ == "__main__":
    unittest.main()
