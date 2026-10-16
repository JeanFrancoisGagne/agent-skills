"""Complete Python diff sides keep their source namespace and data checks."""
import difflib
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autoreview_source_guard.py"
for value in sys.argv[1:]:
    if value.startswith("--guard="):
        SCRIPT = Path(value.split("=", 1)[1])
        sys.argv.remove(value)
SPEC = importlib.util.spec_from_file_location("complete_python_diff_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class CompletePythonDiffSourceGuardTests(unittest.TestCase):
    source = "import re\n_NUMERIC_TOKEN = re.compile(r'[0-9]+(?:[eE][+-]?[0-9]+)?')\n"

    def section(self, source=None, side="+", path="grammar.py"):
        source = self.source if source is None else source
        lines = source.splitlines()
        old = "/dev/null" if side == "+" else "a/" + path
        new = "b/" + path if side == "+" else "/dev/null"
        coordinates = "-0,0 +1," + str(len(lines)) if side == "+" else "-1," + str(len(lines)) + " +0,0"
        return ("diff --git a/" + path + " b/" + path + "\n"
                + "--- " + old + "\n+++ " + new + "\n@@ " + coordinates + " @@\n"
                + "".join(side + line + "\n" for line in lines))

    def check(self, section, refused=False, paths=None, sections=None):
        paths = ["grammar.py"] if paths is None else paths
        sections = [section] if sections is None else sections
        if refused:
            with self.assertRaises(SystemExit):
                GUARD.require_safe_diff(paths, section, sections)
        else:
            GUARD.require_safe_diff(paths, section, sections)

    def test_complete_creation_preserves_public_regex_namespace(self):
        self.check(self.section())

    def test_complete_deletion_preserves_public_regex_namespace(self):
        self.check(self.section(side="-"))


    def test_complete_real_public_module_on_both_sides(self):
        public = (Path(__file__).parent / "fixtures/query_planner_public.py").read_text(encoding="utf-8")
        for side in ("+", "-"):
            with self.subTest(side=side):
                self.check(self.section(public, side=side))

    def test_wrong_line_count_withholds_namespace(self):
        for side in ("+", "-"):
            section = self.section(side=side)
            coordinate = "+1,2" if side == "+" else "-1,2"
            for count in ("1", "3"):
                with self.subTest(side=side, count=count):
                    self.check(section.replace(coordinate, coordinate[:-1] + count), refused=True)

    def test_initial_coordinates_must_prove_a_complete_side(self):
        pairs = ((self.section(), "-0,0 +1,2", "-0,0 +2,2"),
                 (self.section(), "-0,0 +1,2", "-1,0 +1,2"),
                 (self.section(side="-"), "-1,2 +0,0", "-2,2 +0,0"),
                 (self.section(side="-"), "-1,2 +0,0", "-1,2 +1,0"))
        for section, old, new in pairs:
            with self.subTest(coordinates=new):
                self.check(section.replace(old, new), refused=True)

    def test_malformed_headers_and_unknown_sides_stay_refused(self):
        section = self.section()
        variants = (section.replace("--- /dev/null", "--- a/grammar.py"),
                    section.replace("+++ b/grammar.py", "+++ /dev/null"),
                    section.replace("--- /dev/null\n", ""),
                    section.replace("+++ b/grammar.py", "+++ b/grammar.py\n+++ b/grammar.py"),
                    section.replace("@@ -0,0 +1,2 @@", "@@ -0,0 +1,2 @"),
                    section.replace("@@ -0,0 +1,2 @@", "@@ invalid @@"))
        for index, content in enumerate(variants):
            with self.subTest(case=index):
                self.check(content, refused=True)

    def test_multiple_hunks_cannot_join_their_namespaces(self):
        for side in ("+", "-"):
            section = self.section(side=side)
            coordinate = "-0,0 +8,1" if side == "+" else "-8,1 +0,0"
            section = section.replace(side + "_NUMERIC_TOKEN", "@@ " + coordinate + " @@\n" + side + "_NUMERIC_TOKEN")
            with self.subTest(side=side):
                self.check(section, refused=True)

    def test_missing_import_and_rebinding_on_either_side_stay_refused(self):
        sources = (self.source.removeprefix("import re\n"),
                   self.source.replace("import re\n", "import re\nre.compile = replacement\n"),
                   self.source.replace("import re\n", "import custom as re\n"))
        for side in ("+", "-"):
            for index, source in enumerate(sources):
                with self.subTest(side=side, case=index):
                    self.check(self.section(source, side=side), refused=True)

    def test_real_three_line_hunk_stays_refused_with_complete_context(self):
        public = (Path(__file__).parent / "fixtures/query_planner_public.py").read_text(encoding="utf-8")
        revised = public.replace("_NUMERIC_TOKEN = re.compile(", "_NUMERIC_TOKEN = re.compile( ", 1)
        section = "diff --git a/grammar.py b/grammar.py\n" + "".join(difflib.unified_diff(
            public.splitlines(True), revised.splitlines(True), fromfile="a/grammar.py", tofile="b/grammar.py", n=3))
        self.check(section, refused=True)
        with GUARD.captured_source_context((("grammar.py", revised),)):
            self.check(section, refused=True)

    def test_creation_new_values_and_deletion_old_values_stay_scanned(self):
        opaque = "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"
        sources = (self.source + "access_token = " + repr(opaque) + "\n",
                   self.source.rstrip() + " or " + repr(opaque) + "\n")
        for side in ("+", "-"):
            for index, source in enumerate(sources):
                with self.subTest(side=side, case=index):
                    self.check(self.section(source, side=side), refused=True)

    def test_every_side_and_section_keeps_its_own_values(self):
        bad = self.source + "access_token = 'PUBLIC_SYNTHETIC_CREDENTIAL_DATA'\n"
        for bad_side in ("+", "-"):
            good_side = "-" if bad_side == "+" else "+"
            good = self.section(side=good_side, path="good.py")
            unsafe = self.section(bad, side=bad_side, path="bad.py")
            for sections in ([good, unsafe], [unsafe, good]):
                with self.subTest(side=bad_side, unsafe_first=sections[0] == unsafe):
                    self.check("".join(sections), refused=True, paths=["good.py", "bad.py"], sections=sections)

    def test_other_files_and_new_versions_cannot_supply_an_old_namespace(self):
        named_import = self.section("import re\n", side="-", path="old.py")
        no_import = self.section(self.source.removeprefix("import re\n"), path="new.py")
        for sections in ([named_import, no_import], [no_import, named_import]):
            with self.subTest(old_import_first=sections[0] == named_import):
                self.check("".join(sections), refused=True, paths=["old.py", "new.py"], sections=sections)
        modified = ("diff --git a/grammar.py b/grammar.py\n--- a/grammar.py\n+++ b/grammar.py\n"
                    "@@ -1,2 +1,2 @@\n import re\n"
                    "-_NUMERIC_TOKEN = re.compile(r'[0-9]+')\n"
                    "+_NUMERIC_TOKEN = re.compile(r'[0-9]*')\n")
        with GUARD.captured_source_context((("grammar.py", self.source),)):
            self.check(modified, refused=True)

    def test_metadata_and_unexpected_paths_keep_the_raw_scan(self):
        section = self.section()
        self.check(section.replace(" @@\n", " @@ access_token = 'PUBLIC_SYNTHETIC_CREDENTIAL_DATA'\n", 1), refused=True)
        self.check(section, refused=True, paths=["different.py"])

    def test_actual_source_semicolon_is_not_removed(self):
        for side in ("+", "-"):
            with self.subTest(side=side):
                self.check(self.section(";\n" + self.source, side=side), refused=True)

    def test_text_and_unowned_hunks_do_not_gain_a_typed_waiver(self):
        self.check(self.section(path="bundle.txt"), refused=True, paths=["bundle.txt"])
        section = self.section()
        hunk = section[section.index("@@"):]
        self.check(hunk, refused=True, sections=[hunk])


if __name__ == "__main__":
    unittest.main()
