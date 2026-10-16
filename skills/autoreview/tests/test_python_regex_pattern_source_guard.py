"""Grammar patterns keep their argument role without approving credential data."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autoreview_source_guard.py"
SPEC = importlib.util.spec_from_file_location("regex_pattern_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def opaque():
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"


class PythonRegexPatternGuardTests(unittest.TestCase):
    pattern = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|[<>{}\[\]:;,?&|]"

    def check_source(self, source, refused=False):
        if refused:
            with self.assertRaises(SystemExit):
                GUARD.require_safe_source("file source", "grammar.py", source)
        else:
            GUARD.require_safe_source("file source", "grammar.py", source)

    def assignment(self, pattern=None, value="text", suffix=""):
        selected = repr(self.pattern) if pattern is None else pattern
        return "import re\n" + "token" + " = re.match(" + selected + ", " + value + ")" + suffix + "\n"

    def test_exact_ambient_type_function(self):
        source = SCRIPT.read_text(encoding="utf-8")
        node = next(part for part in ast.parse(source).body
                    if isinstance(part, ast.FunctionDef) and part.name == "typescript_ambient_type_token")
        self.check_source("import re\n\n" + ast.get_source_segment(source, node) + "\n")

    def test_pattern_is_grammar_metadata(self):
        self.check_source(self.assignment())

    def test_every_other_literal_and_suffix_stays_refused(self):
        value = json.dumps(opaque())
        sources = (
            self.assignment(value=value),
            self.assignment(suffix=" or " + value),
            self.assignment(suffix=" + " + value),
            self.assignment(pattern=value),
            self.assignment(pattern=repr(self.pattern) + " + " + value),
            self.assignment(pattern=repr("".join("[" + char + "]" for char in opaque()))),
            self.assignment(pattern=repr("[A-Z]+" + opaque())),
            self.assignment(value="text.strip(" + value + ")"),
            self.assignment(pattern=repr("[A-Z")),
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index):
                self.check_source(source, refused=True)

    def test_re_spelling_does_not_establish_stdlib_origin(self):
        source = self.assignment()
        sources = (
            source.replace("import re\n", ""),
            source.replace("import re", "import custom as re"),
            source.replace("import re\n", "import re\nre = replacement\n"),
            source.replace("import re\n", "import re\nre.match = replacement\n"),
            source.replace("import re\n", "import re\nalias = re\nalias.match = replacement\n"),
            "import re\ndef parse(re):\n    " + source.split("\n", 1)[1],
            source.replace("re.match", "re.sub"),
        )
        for index, content in enumerate(sources):
            with self.subTest(case=index):
                self.check_source(content, refused=True)

    def test_module_alias_and_function_escape_stays_refused(self):
        source = self.assignment()
        mutations = (
            "import re as other\nother.match = replacement\n",
            "from re import match as other\nother.__globals__['match'] = replacement\n",
            "helper = re.compile\nhelper.__globals__['match'] = replacement\n",
            "import sys\nsys.modules['re'].match = replacement\n",
            "setattr(re, 'match', replacement)\n",
            "re.__dict__['match'] = replacement\n",
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                self.check_source(source.replace("import re\n", "import re\n" + mutation), refused=True)


if __name__ == "__main__":
    unittest.main()
