"""Case-label roles require native string and comment boundaries."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_case_guard", ROOT / "scripts/autoreview_source_guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def opaque():
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"


class NativeCaseContextTests(unittest.TestCase):
    def credential(self, key="token"):
        return "case " + json.dumps(key) + ": " + json.dumps(opaque()) + "\n"

    def status(self):
        return 'case "ok-token":\n    return ("Heartbeat ok", .green)\n'

    def refuse(self, source, path="status.swift"):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source("file source", path, source)

    def accept(self, source):
        GUARD.require_safe_source("file source", "status.swift", source)

    def test_multiline_interior_quote_cannot_expose_case_data(self):
        quote = chr(34) * 3
        for key in ("token", "password"):
            with self.subTest(field=key):
                self.refuse("let note = " + quote + '\n"\n' + self.credential(key) + quote + "\n")

    def test_extended_multiline_delimiters_keep_all_content_noncode(self):
        quote = chr(34) * 3
        for count in (1, 2, 3):
            with self.subTest(hash_count=count):
                hashes = "#" * count
                inside = quote + hashes[:-1] + '\n"\n'
                self.refuse("let note = " + hashes + quote + "\n" + inside + self.credential() + quote + hashes + "\n")

    def test_nested_swift_block_comments_do_not_expose_case_data(self):
        self.refuse("/* outer\n/* inner */\n" + self.credential() + "*/\n")

    def test_interpolated_multiline_string_keeps_following_content_noncode(self):
        quote = chr(34) * 3
        self.refuse("let note = " + quote + '\n\\("inner")\n"\n' + self.credential() + quote + "\n")

    def test_raw_interpolation_keeps_its_parent_string_context(self):
        quote = chr(34) * 3
        self.refuse("let note = #" + quote + '\n\\#("inner")\n"\n' + self.credential() + quote + "#\n")

    def test_unterminated_multiline_string_grants_no_case_role(self):
        self.refuse("let note = " + chr(34) * 3 + '\n"\n' + self.credential())

    def test_unterminated_block_comment_grants_no_case_role(self):
        self.refuse("/* outer\n/* inner */\n" + self.credential())

    def test_unproved_extended_regex_grants_no_case_role(self):
        self.refuse("let pattern = #/\n" + self.credential() + "/#\n")

    def test_completed_multiline_string_leaves_real_case_visible(self):
        quote = chr(34) * 3
        self.accept("let note = " + quote + '\n"\n' + quote + "\n" + self.status())

    def test_completed_raw_multiline_string_leaves_real_case_visible(self):
        quote = chr(34) * 3
        for count in (1, 2, 3):
            hashes = "#" * count
            self.accept("let note = " + hashes + quote + '\n"\n' + quote + hashes + "\n" + self.status())

    def test_raw_single_line_string_uses_matching_hash_count(self):
        self.accept('let note = ##"a quote " and \\#" still text"##\n' + self.status())

    def test_completed_interpolation_with_nested_string_keeps_real_case(self):
        self.accept('let note = "prefix \\("inner") suffix"\n' + self.status())

    def test_completed_raw_interpolation_keeps_real_case(self):
        self.accept('let note = #"prefix \\#("inner") suffix"#\n' + self.status())

    def test_completed_nested_comment_keeps_real_case(self):
        self.accept('/* outer "\n/* inner */\n*/\n' + self.status())

    def test_line_comment_quotes_do_not_change_the_next_line(self):
        self.accept('// an unmatched " ends with the comment\n' + self.status())

    def test_case_body_assignment_stays_visible_after_native_context(self):
        quote = chr(34) * 3
        source = "let note = " + quote + '\n"\n' + quote + "\n" + self.status()
        self.refuse(source + "password = " + json.dumps(opaque()) + "\n")

    def test_native_case_role_keeps_raw_marker_checks(self):
        self.refuse(self.status() + 'let value = "' + "sk-" + opaque() + '"\n')

    def test_other_unproved_dialects_cannot_borrow_javascript_quotes(self):
        quote = chr(34) * 3
        for suffix in (".cs", ".java", ".kt", ".py"):
            with self.subTest(suffix=suffix):
                self.refuse("let note = " + quote + '\n"\n' + self.credential() + quote + "\n", "status" + suffix)

    def test_jsx_text_cannot_borrow_a_javascript_case_role(self):
        for suffix in (".jsx", ".tsx"):
            with self.subTest(suffix=suffix):
                self.refuse("const view = <pre>\n" + self.credential() + "</pre>;\n", "status" + suffix)


    def test_single_quoted_swift_data_is_not_a_native_case_label(self):
        source = "case 'token': '" + opaque() + "'\n"
        self.refuse(source)

    def test_escaped_multiline_closer_cannot_expose_case_data(self):
        quote = chr(34) * 3
        for count in (0, 1, 2):
            hashes = "#" * count
            source = "let note = " + hashes + quote + "\n" + "\\" + hashes + quote + "\n"
            self.refuse(source + self.credential() + quote + hashes + "\n")

    def test_interpolation_comments_do_not_close_parentheses(self):
        self.accept('let note = "prefix \\( /* ) */ ("inner") ) suffix"\n' + self.status())


    def test_single_line_regex_quotes_cannot_change_following_string_context(self):
        quote = chr(34)
        for regex_quotes in (1, 2, 3, 4):
            for body_quotes in (0, 1, 2):
                with self.subTest(regex_quotes=regex_quotes, body_quotes=body_quotes):
                    source = "let pattern = /" + quote * regex_quotes + "/\nlet note = " + quote * 3 + "\n"
                    self.refuse(source + quote * body_quotes + "\n" + self.credential() + quote * 3 + "\n")

    def test_division_with_whitespace_keeps_real_case(self):
        self.accept("let age = timestamp / 1000\n" + self.status())

    def test_backtick_identifier_quotes_do_not_start_a_string(self):
        self.accept('let `note"name` = source\n' + self.status())

    def test_crlf_multiline_data_keeps_its_string_context(self):
        quote = chr(34) * 3
        source = "let note = " + quote + '\n"\n' + self.credential() + quote + "\n"
        self.refuse(source.replace("\n", "\r\n"))


    def test_excess_hashes_do_not_prove_a_raw_closing_boundary(self):
        quote = chr(34) * 3
        for count in (1, 2):
            hashes = "#" * count
            source = "let note = " + hashes + quote + "\n" + quote + hashes + "#\n"
            self.refuse(source + self.credential() + quote + hashes + "\n")


    def diff(self, source, suffix=".swift", complete=False, deleted=False):
        path = "status" + suffix
        lines = source.splitlines()
        old = "/dev/null" if complete else "a/" + path
        new = "/dev/null" if deleted else "b/" + path
        header = "diff --git a/" + path + " b/" + path + "\n--- " + old + "\n+++ " + new + "\n"
        if deleted:
            hunk = f"@@ -1,{len(lines)} +0,0 @@\n"
            prefix = "-"
        else:
            hunk = f"@@ -0,0 +1,{len(lines)} @@\n" if complete else f"@@ -40,0 +41,{len(lines)} @@\n"
            prefix = "+"
        return header + hunk + "".join(prefix + line + "\n" for line in lines)

    def refuse_diff(self, patch, suffix=".swift"):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_diff(["status" + suffix], patch, [patch])

    def test_partial_hunks_cannot_establish_initial_string_context(self):
        for suffix in (".swift", ".js", ".ts"):
            with self.subTest(suffix=suffix):
                self.refuse_diff(self.diff(self.credential(), suffix), suffix)

    def test_complete_creation_keeps_real_case_role(self):
        patch = self.diff(self.status(), complete=True)
        GUARD.require_safe_diff(["status.swift"], patch, [patch])

    def test_complete_deletion_keeps_real_case_role(self):
        patch = self.diff(self.status(), deleted=True)
        GUARD.require_safe_diff(["status.swift"], patch, [patch])

    def test_complete_creation_keeps_multiline_data_denied(self):
        quote = chr(34) * 3
        source = "let note = " + quote + '\n"\n' + self.credential() + quote + "\n"
        self.refuse_diff(self.diff(source, complete=True))

    def test_disconnected_hunks_cannot_borrow_missing_quote_context(self):
        patch = self.diff("let note = " + chr(34) * 3 + "\n")
        patch += "@@ -80,0 +81,1 @@\n+" + self.credential()
        self.refuse_diff(patch)

    def test_wrong_creation_count_grants_no_complete_source_role(self):
        patch = self.diff(self.credential(), complete=True).replace("+1,1 @@", "+1,2 @@")
        self.refuse_diff(patch)

    def test_partial_refusal_restores_complete_source_context(self):
        self.refuse_diff(self.diff(self.credential()))
        self.accept(self.status())

    def test_combined_hunk_does_not_establish_complete_source(self):
        patch = "diff --git a/status.swift b/status.swift\n--- a/status.swift\n+++ b/status.swift\n"
        patch += "@@@ -40,0 -40,0 +41,1 @@@\n++" + self.credential()
        self.refuse_diff(patch)



    def test_conflicting_file_markers_grant_no_complete_source_role(self):
        patch = self.diff(self.credential(), complete=True)
        patch = patch.replace("--- /dev/null\n", "--- /dev/null\n--- a/status.swift\n")
        self.refuse_diff(patch)

if __name__ == "__main__":
    unittest.main()
