"""Compiled public regex metadata retains the scanner's origin and data checks."""
import importlib.util
import ast
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autoreview_source_guard.py"
SPEC = importlib.util.spec_from_file_location("compiled_regex_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PythonCompiledRegexSourceGuardTests(unittest.TestCase):
    def check(self, source, refused=False):
        ast.parse(source)
        if refused:
            with self.assertRaises(SystemExit):
                GUARD.require_safe_source("public compiled regex", "grammar.py", source)
        else:
            GUARD.require_safe_source("public compiled regex", "grammar.py", source)

    def compiled(self, pattern, prefix="import re\n", suffix=""):
        return prefix + "access_token = re.compile(" + repr(pattern) + ")" + suffix + "\n"

    def test_exact_numeric_compile_owner(self):
        source = (Path(__file__).parent / "fixtures/compiled_numeric_owner.py").read_text(encoding="utf-8")
        GUARD.require_safe_source("public compiled regex", "query_planner.py", source)

    def test_complete_reviewed_planner_keeps_its_actual_namespace(self):
        source = (Path(__file__).parent / "fixtures/query_planner_public.py").read_text(encoding="utf-8")
        GUARD.require_safe_source("public compiled regex", "query_planner.py", source)

    def test_hunk_without_namespace_proof_remains_refused(self):
        source = (Path(__file__).parent / "fixtures/compiled_numeric_owner.py").read_text(encoding="utf-8")
        content = source.removeprefix("import re\n")
        section = ("diff --git a/grammar.py b/grammar.py\n--- a/grammar.py\n+++ b/grammar.py\n"
                   "@@ -0,0 +1," + str(len(content.splitlines())) + " @@\n"
                   + "".join("+" + line + "\n" for line in content.splitlines()))
        with self.assertRaises(SystemExit):
            GUARD.require_safe_diff(["grammar.py"], section, [section])

    def test_numeric_markers_follow_structure_not_a_fixed_letter(self):
        for pattern in (r"(?<![0-9])[0-9]+(?:[pP][+-]?[0-9]+)?(?![0-9])",
                        r"\d+(?:[qQ][+-]?\d+)?"):
            with self.subTest(pattern=pattern):
                self.check(self.compiled(pattern))

    def test_lookaround_without_letters_is_grammar(self):
        self.check(self.compiled(r"(?<![0-9])[0-9]+(?![0-9])"))

    def test_match_uses_the_same_grammar_owner(self):
        self.check("import re\ndef read(text):\n"
                   "    token = re.match(r'[0-9]+(?:[pP][+-]?[0-9]+)?', text)\n")

    def test_literal_and_encoded_credentials_remain_refused(self):
        opaque = "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"
        patterns = (opaque, "sk-" + opaque,
                    "".join("[" + char + "]" for char in opaque),
                    "[0-9]+" + "".join("[" + char.lower() + char.upper() + "]"
                                             for char in opaque if char.isalpha()),
                    "[0-9]+" + "".join("[" + char + char.upper() + "][0-9]+"
                                             for char in "private"),
                    "[A-Z]+" + opaque)
        for index, pattern in enumerate(patterns):
            with self.subTest(case=index):
                self.check(self.compiled(pattern), refused=True)

    def test_case_pairs_without_numeric_neighbors_remain_refused(self):
        for pattern in (r"[pP][0-9]+", r"[0-9]+[pP]", r"[A-Z]+[pP][0-9]+",
                        r"[0-9]+[pP][A-Z]+", r"[0-9]+[pP][pP][0-9]+",
                        r"[0-9]+|[pP][0-9]+", r"[0-9]+[pP]|[0-9]+"):
            with self.subTest(pattern=pattern):
                self.check(self.compiled(pattern), refused=True)

    def test_marker_and_numeric_atom_cannot_encode_repeated_static_letters(self):
        for pattern in (r"[0-9]+[pP]{24}[0-9]+", r"[0-9]+([pP]){24}[0-9]+",
                        r"[0-9]+(?:[pP][0-9]{0}){24}",
                        r"[0-9]+(?:[pP][0-9]{00}){24}",
                        r"[0-9]+(?:[pP][0-9]{00,24}){24}"):
            with self.subTest(pattern=pattern):
                self.check(self.compiled(pattern), refused=True)

    def test_every_other_argument_and_suffix_remains_refused(self):
        source = self.compiled(r"[0-9]+")
        opaque = repr("A7f9K2m4Q8v6" + "N3x5R1p0T9z8")
        variants = (source.rstrip() + " or " + opaque + "\n",
                    source.rstrip() + " + " + opaque + "\n",
                    source.replace("re.compile('[0-9]+')", "re.compile('[0-9]+', " + opaque + ")"),
                    source.replace("re.compile('[0-9]+')", "re.compile('[0-9]+', flags=" + opaque + ")"),
                    source.replace("re.compile('[0-9]+')", "re.compile('[0-9]+' + " + opaque + ")"))
        for index, content in enumerate(variants):
            with self.subTest(case=index):
                self.check(content, refused=True)

    def test_namespace_origin_is_required_and_must_remain_intact(self):
        source = self.compiled(r"[0-9]+")
        variants = (source.replace("import re\n", ""),
                    source.replace("import re", "import custom as re"),
                    source.replace("import re\n", "import re\nre = replacement\n"),
                    source.replace("import re\n", "import re\nre.compile = replacement\n"),
                    source.replace("import re\n", "import re\nalias = re\nalias.compile = replacement\n"),
                    source.replace("import re\n", "import re\nhelper = re.compile\n"),
                    source.replace("import re\n", "import re\nimport importlib as loader\nother = loader.import_module('re')\nother.compile = replacement\n"),
                    source.replace("import re\n", "import re\nfrom sys import modules as cache\ncache['re'].compile = replacement\n"),
                    "import re\ndef read(re):\n    " + source.split("\n", 1)[1],
                    source + "re.compile = replacement\n")
        for index, content in enumerate(variants):
            with self.subTest(case=index):
                self.check(content, refused=True)

    def test_unknown_and_fabricated_callable_names_remain_refused(self):
        source = self.compiled(r"[0-9]+")
        variants = (source.replace("re.compile", "re.unknown"),
                    source.replace("re.compile", "compile"),
                    source.replace("import re\n", "re = SimpleNamespace(compile=handler)\n"),
                    source.replace("import re\n", "from re import compile\n").replace("re.compile", "compile"))
        for index, content in enumerate(variants):
            with self.subTest(case=index):
                self.check(content, refused=True)

    def test_invalid_regex_and_singleton_encoded_letters_remain_refused(self):
        for pattern in (r"[0-9", r"[p][0-9]+", r"[0-9]+(?:[pP][0-9]+"):
            with self.subTest(pattern=pattern):
                self.check(self.compiled(pattern), refused=True)


if __name__ == "__main__":
    unittest.main()
