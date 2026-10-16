"""Large source modules keep the same parameter and credential decisions."""
import importlib.util
from pathlib import Path
import random
import re
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('parameter_cost_guard', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class JavascriptParameterScanCostTests(unittest.TestCase):
    def test_method_name_matches_original_boundaries(self):
        original = r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*$'
        prefixes = ['', '.', '?.', '9', 'é', '_', '$', '{', ';', ',', '}']
        names = ['', 'read', 'if', '$read', '_read', 'readé', 'éread', '9read', 'a.b']
        spaces = ['', ' ', '\t\n', '\u2003']
        for prefix in prefixes:
            for name in names:
                for space in spaces:
                    code = prefix + name + space + '(input) {}'
                    start = code.index('(')
                    expected = re.search(original, code[:start])
                    actual = GUARD.javascript_method_name(code, start)
                    with self.subTest(prefix=prefix, name=name, space=space):
                        self.assertEqual(None if actual is None else (actual.span(), actual.group(1)),
                                         None if expected is None else (expected.span(), expected.group(1)))
        rng = random.Random(42)
        alphabet = 'aZ09_$é². ;,}\t\n\u2003\u0301'
        for _ in range(1000):
            code = ''.join(rng.choices(alphabet, k=rng.randrange(1, 50)))
            expected = re.search(original, code)
            actual = GUARD.javascript_method_name(code, len(code))
            self.assertEqual(None if actual is None else (actual.span(), actual.group(1)),
                             None if expected is None else (expected.span(), expected.group(1)))

    def test_grouped_member_callee_search_is_bounded(self):
        code = 'const ' + ('a' * 5000) + ' = value;\nconst chosen = (input).value;'
        search = re.search

        def measured(pattern, string, flags=0):
            if pattern == r'[A-Za-z_$][\w$]*$':
                self.assertLessEqual(len(string), 128)
            return search(pattern, string, flags)

        with patch.object(GUARD.re, 'search', side_effect=measured):
            normalized = GUARD.javascript_grouped_member_code(code)
        self.assertIn('input.value', normalized)

    def test_method_lookup_has_a_linear_regex_input_budget(self):
        code = ('consume(supplied);\n' * 300
                + 'const owner = { configure(input) { return input; } };')
        pairs = GUARD.javascript_scope_pairs(code)
        search = re.search
        scanned = 0

        def measured(pattern, string, flags=0):
            nonlocal scanned
            if pattern == r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*$':
                scanned += len(string)
                self.assertLessEqual(scanned, len(code) * 4)
            return search(pattern, string, flags)

        with patch.object(GUARD.re, 'search', side_effect=measured):
            bindings = GUARD.javascript_method_parameter_bindings(code, pairs)
        self.assertEqual({name for _, name in bindings.values()}, {'input'})

    def test_distinct_roots_share_one_immutable_parameter_parse(self):
        code = 'function read(input, other) { return input; }'
        GUARD.javascript_code_parameter.cache_clear()
        with patch.object(GUARD, 'javascript_method_parameter_bindings',
                          wraps=GUARD.javascript_method_parameter_bindings) as parse:
            self.assertTrue(GUARD.javascript_code_parameter(code, 'input'))
            self.assertTrue(GUARD.javascript_code_parameter(code, 'other'))
            for index in range(30):
                self.assertFalse(GUARD.javascript_code_parameter(code, 'missing' + str(index)))
        self.assertEqual(parse.call_count, 1)

    def test_repeated_initializer_lookup_parses_once_and_returns_owned_lists(self):
        text = 'function read(input) { const selected = input.value; return selected; }'
        code = GUARD.javascript_binding_code(text)
        finditer = re.finditer
        calls = 0

        def measured(pattern, string, flags=0):
            nonlocal calls
            if pattern == r'(?<![\w$.])selected(?![\w$])':
                calls += 1
            return finditer(pattern, string, flags)

        with patch.object(GUARD.re, 'finditer', side_effect=measured):
            first = GUARD.javascript_binding_initializers(text, code, 'selected')
            first.append('caller-owned mutation')
            for _ in range(30):
                self.assertEqual(GUARD.javascript_binding_initializers(text, code, 'selected'), [' input.value'])
        self.assertEqual(calls, 1)

    def test_repeated_initializer_normalization_reuses_exact_source(self):
        source = 'const uniqueSelection = (input).selected;'
        with patch.object(GUARD, 'javascript_inline_type_text', wraps=GUARD.javascript_inline_type_text) as parse:
            expected = GUARD.javascript_initializer_value_code(source)
            for _ in range(30):
                self.assertEqual(GUARD.javascript_initializer_value_code(source), expected)
            self.assertEqual(parse.call_count, 1)

    def test_repeated_mutation_proof_reuses_only_the_exact_capture(self):
        text = 'const state = {value: supplied}; consume({token: state.value});'
        code = GUARD.javascript_binding_code(text)
        with patch.object(GUARD, 'javascript_selected_alias_paths', return_value=None) as parse:
            for _ in range(30):
                self.assertTrue(GUARD.javascript_selected_mutation_risk(text, code, ['state', 'value']))
            self.assertEqual(parse.call_count, 1)
            with GUARD.captured_source_context([('caller.ts', text)]):
                self.assertTrue(GUARD.javascript_selected_mutation_risk(text, code, ['state', 'value']))
            self.assertEqual(parse.call_count, 2)
            with GUARD.captured_source_context([('caller.ts', text + '\nchanged();')]):
                self.assertTrue(GUARD.javascript_selected_mutation_risk(text, code, ['state', 'value']))
            self.assertEqual(parse.call_count, 3)

    def test_repeated_symbol_proof_keeps_ancestor_and_capture_keys(self):
        text = 'function uniqueRead(input) { return input; }'
        with patch.object(GUARD, 'javascript_code_parameter', wraps=GUARD.javascript_code_parameter) as parse:
            self.assertTrue(GUARD.javascript_code_symbol_reference(text, 'uniqueRead'))
            count = parse.call_count
            self.assertTrue(GUARD.javascript_code_symbol_reference(text, 'uniqueRead'))
            self.assertEqual(parse.call_count, count)
            identity = (None, text, 'uniqueRead', False)
            self.assertIsNone(GUARD.javascript_code_symbol_reference(text, 'uniqueRead', ancestors=frozenset({identity})))
        with GUARD.captured_source_context([('caller.ts', text)]):
            self.assertTrue(GUARD.javascript_code_symbol_reference(text, 'uniqueRead'))

    def test_cache_keeps_source_revisions_and_malformed_owners_separate(self):
        good = 'const owner = { read(input) { return input; } };'
        revised = good.replace('input', 'other')
        malformed = 'function read(input) { return input; '
        self.assertTrue(GUARD.javascript_code_parameter(good, 'input'))
        self.assertFalse(GUARD.javascript_code_parameter(revised, 'input'))
        self.assertTrue(GUARD.javascript_code_parameter(revised, 'other'))
        self.assertFalse(GUARD.javascript_code_parameter(malformed, 'input'))
        self.assertIsInstance(GUARD.javascript_code_parameter_names(good), frozenset)
        self.assertEqual(GUARD.javascript_code_parameter_names.cache_info().maxsize, 8)

    def test_partial_owner_failure_grants_no_parameters(self):
        code = 'function read(input) { return input; }'
        GUARD.javascript_code_parameter.cache_clear()
        GUARD.javascript_code_parameter_names.cache_clear()
        with patch.object(GUARD, 'javascript_arrow_parameter_bindings', return_value=None):
            self.assertFalse(GUARD.javascript_code_parameter(code, 'input'))
        GUARD.javascript_code_parameter.cache_clear()
        GUARD.javascript_code_parameter_names.cache_clear()
        self.assertTrue(GUARD.javascript_code_parameter(code, 'input'))

    def test_method_parameters_keep_literal_and_mutation_refusal(self):
        literal = repr('A7f9K2m4Q8v6' + 'N3x5R1p0T9z8')
        accepted = 'const owner = { read(input) { return {token: input.token}; } };'
        GUARD.require_safe_source('file source', 'owner.ts', accepted)
        refused = [
            accepted.replace('input.token', literal),
            'const owner = { read(input) { input.token = ' + literal + '; return {token: input.token}; } };',
            'const state={value:supplied}; const owner={read(input){state.value=' + literal
            + ';}}; unknown(owner); consume({token:state.value});',
        ]
        for source in refused:
            with self.subTest(source_kind=refused.index(source)):
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source('file source', 'owner.ts', source)


if __name__ == '__main__':
    unittest.main()
