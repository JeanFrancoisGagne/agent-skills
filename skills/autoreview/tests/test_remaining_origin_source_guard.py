"""Public guard controls for exact source syntax and synthetic redaction data."""
import hashlib
import json
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('remaining_guard', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)

def field(key, value):
    return repr(key) + ': ' + value

def opaque():
    return 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'

def notation():
    return 'scheme://' + 'user:' + 'pass@host'

def demo():
    return 'sk-or-v1-' + 'abcdef' + '0123456789'

class RemainingOriginGuardTests(unittest.TestCase):
    def accept(self, source, path):
        GUARD.require_safe_source('file source', path, source)

    def refuse(self, source, path):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', path, source)

    def test_compound_control_colon_is_not_an_assignment(self):
        self.accept('if pages_done == 1 and (not page_token):\n    print("No messages found")\n', 'entry.py')

    def test_control_body_and_walrus_credentials_stay_refused(self):
        self.refuse('if pages_done == 1 and (not page_token):\n    token = ' + repr(opaque()) + '\n', 'entry.py')
        self.refuse('if (token := ' + repr(opaque()) + '):\n    pass\n', 'entry.py')

    def test_fixture_kind_matches_prefixed_credential_field(self):
        self.accept('environment = {' + field('XAI_API_KEY', repr('fixture-key')) + '}\n', 'entry.py')

    def test_fixture_kind_mismatch_and_opaque_suffix_stay_refused(self):
        self.refuse('environment = {' + field('PASSWORD', repr('fixture-key')) + '}\n', 'entry.py')
        self.refuse('environment = {' + field('XAI_API_KEY', repr('fixture-key-' + opaque())) + '}\n', 'entry.py')

    def test_sequential_redaction_fixture_has_an_actual_negative_assertion(self):
        self.accept('const result = record("OPENROUTER_API_KEY=' + demo() + '");\nexpect(serialized).not.toContain(' + repr(demo()) + ');', 'entry.test.ts')

    def test_redaction_label_cannot_hide_an_opaque_provider_key(self):
        for value in (demo()[:-1] + 'x', 'sk-or-v1-' + opaque()):
            self.refuse('const result = record("OPENROUTER_API_KEY=' + value + '");\nexpect(serialized).not.toContain(' + repr(value) + ');', 'entry.test.ts')
        self.refuse('const result = record("OPENROUTER_API_KEY=' + demo() + '");\n// expect(serialized).not.toContain(' + repr(demo()) + ');', 'entry.test.ts')

    def test_comment_uri_metasyntax_is_a_reference(self):
        self.accept('// URL password slots (' + chr(96) + notation() + chr(96) + ')\nconst value = input;', 'entry.ts')

    def test_uri_credentials_and_noncomment_notation_stay_refused(self):
        for source in ('// https://reader:' + opaque() + '@example.invalid/db', 'const value = "' + notation() + '";', '// ' + chr(96) + 'scheme://' + 'user:pass@example.invalid' + chr(96)):
            self.refuse(source, 'entry.ts')

    def test_quoted_reference_does_not_scan_the_next_literal(self):
        self.accept('print(f"page token={page_token[:20]}")\nparse("Title + Summary")\n', 'entry.py')
        self.accept('const result = record("OPENROUTER_API_KEY=' + demo() + '");\nexpect(serialized).not.toContain(' + repr(demo()) + ');\nexpect(serialized).not.toContain("OPENROUTER_API_KEY=");\nit("word and phrase", () => record("hello"));', 'entry.test.ts')

    def test_selected_spread_preserves_value_and_overrides(self):
        template = 'function selectCapture(input) { const selected = {value: VALUE, index: -1}; return {...selected, count: 1}; } function caller(input) { const selected = selectCapture(input); const ' + 'token' + ' = selected.value; consume({' + 'token' + '}); }'
        self.accept(template.replace('VALUE', 'input'), 'entry.ts')
        self.refuse(template.replace('VALUE', repr(opaque())), 'entry.ts')

    def test_selected_map_filter_and_indices_keep_value_origin(self):
        template = 'function selectCapture(groups: string[]) { const tokens = groups.map((value, index) => ({index, value: VALUE})).filter(({value}) => typeof value === "string" && value.length > 0); const selected = (tokens.length > 1 ? tokens[tokens.length - 1] : tokens[0]) ?? {index: -1, value: groups}; return {...selected, count: tokens.length}; } function caller(groups: string[]) { const selected = selectCapture(groups); const ' + 'token' + ' = selected.value; consume({' + 'token' + '}); }'
        self.accept(template.replace('VALUE', 'value'), 'entry.ts')
        self.refuse(template.replace('VALUE', repr(opaque())), 'entry.ts')

    def source_packet(self, source, path='entry.test.ts'):
        return {'path': path, 'bytes': len(source.encode()), 'sha256': hashlib.sha256(source.encode()).hexdigest(), 'source': source}

    def test_bound_json_source_keeps_native_language_classification(self):
        source = 'const result = record("OPENROUTER_API_KEY=' + demo() + '");\nexpect(serialized).not.toContain(' + repr(demo()) + ');'
        self.accept(json.dumps({'evidence': self.source_packet(source)}), 'packet.json')

    def test_bound_json_source_keeps_credentials_and_duplicate_members_refused(self):
        source = 'const token = ' + repr(opaque()) + ';'
        self.refuse(json.dumps({'evidence': self.source_packet(source)}), 'packet.json')
        uri = '// https://reader:' + opaque() + '@example.invalid/db'
        self.refuse(json.dumps({'evidence': self.source_packet(uri)}), 'packet.json')
        packet = json.dumps(self.source_packet(source))
        self.refuse(packet[:-1] + ', "source": "const value = input;"}', 'packet.json')

    def test_json_source_binding_mismatch_retains_strict_scan(self):
        source = 'const result = record("OPENROUTER_API_KEY=' + demo() + '");\nexpect(serialized).not.toContain(' + repr(demo()) + ');'
        for change in ({'sha256': '0' * 64}, {'bytes': 0}, {'bytes': str(len(source.encode()))}, {'path': 'entry.txt'}):
            packet = self.source_packet(source)
            packet.update(change)
            self.refuse(json.dumps(packet), 'packet.json')


    def test_annotated_empty_and_boolean_values_are_source_scalars(self):
        for source in (
            'def choose(' + 'is_secret' + ': Optional[bool] = None):\n    pass\n',
            'def choose(' + 'is_secret' + ': Optional[bool] = False):\n    pass\n',
            'def choose(' + 'is_secret' + ': bool = True):\n    pass\n',
            'is_secret' + ': Optional[bool] = None\n',
        ):
            self.accept(source, 'entry.py')

    def test_annotations_keep_actual_credential_values_refused(self):
        for value in (repr(opaque()), repr('None'), repr('False')):
            self.refuse('def choose(' + 'api_key' + ': Optional[bool] = ' + value + '):\n    pass\n', 'entry.py')
        self.refuse('def choose(' + 'is_secret' + ': Optional[bool] = None, ' + 'password' + '=' + repr(opaque()) + '):\n    pass\n', 'entry.py')
        for target in ('api_key', 'owner.api_key'):
            self.refuse(target + ': str = ' + repr(opaque()) + '\n', 'entry.py')
        self.refuse('def choose(' + 'api_key' + ': Literal[' + repr(opaque()) + '] = None):\n    pass\n', 'entry.py')

    def test_annotated_parameter_defaults_scan_actual_values(self):
        for header in (
            'def connect(' + 'password' + ': str = VALUE):',
            'async def connect(' + 'password' + ': str = VALUE):',
            'def connect(' + 'password' + ': str = VALUE, /):',
            'def connect(*, ' + 'password' + ': str = VALUE):',
            'def connect(prefix: str = "ordinary", ' + 'password' + ': str = VALUE):',
        ):
            with self.subTest(header_kind=header.split(' ', 1)[0]):
                self.refuse(header.replace('VALUE', repr(opaque())) + '\n    pass\n', 'entry.py')
        self.refuse('def connect(' + 'password' + ': str = ' + repr('https://reader:' + opaque() + '@example.invalid/db') + '):\n    pass\n', 'entry.py')
        self.accept('def connect(' + 'password' + ': str = None):\n    pass\n', 'entry.py')
        self.accept('def connect(' + 'password' + ': str = provided):\n    pass\n', 'entry.py')
        self.accept('def connect(*, ' + 'is_secret' + ': bool = False):\n    pass\n', 'entry.py')


    def test_ambient_declaration_member_is_type_only_in_public_contract_text(self):
        source = 'export declare const Schema: Namespace.Object<{\n    progressToken: Namespace.Optional<Namespace.Union<readonly [Namespace.String, Namespace.Number]>>;\n}>;\n'
        for path in ('contract.txt', 'entry.d.ts'):
            self.accept(source, path)

    def test_ambient_declaration_exemption_cannot_hide_runtime_or_literal_values(self):
        for source in (
            'const value = {progressToken: Namespace.Optional};',
            'export declare const Schema: Namespace.Object<{progressToken: Namespace.Optional<Namespace.String>; password = ' + repr(opaque()) + ';}>;',
            'export declare const Schema: Namespace.Object<{progressToken: makeType(' + repr(opaque()) + ');}>;',
            'export declare const Schema: Namespace.Object<{progressToken: ' + repr(opaque()) + ';}>;',
            'export declare const Schema: Namespace.Object<{progressToken: Namespace.String;}> = ' + repr(opaque()) + ';',
            '// export declare const Schema: Namespace.Object<{\nprogressToken: Namespace.Optional<Namespace.String>;\n}>;',
            'export declare const Schema: Namespace.Object<{\nprogressToken: Namespace.Optional<Namespace.String>;\n',
        ):
            self.refuse(source, 'contract.txt')
        self.refuse('export declare const Schema: Namespace.Object<{progressToken: Namespace.String;}>;\npassword = ' + repr(opaque()), 'contract.txt')


    def test_ambient_generic_literals_and_fake_owners_stay_refused(self):
        for expression in (
            'Namespace.Optional<' + repr(opaque()) + '>',
            'Namespace.Optional<Namespace.String | ' + repr(opaque()) + '>',
        ):
            source = 'export declare const Schema: Namespace.Object<{progressToken: ' + expression + ';}>;'
            for wrapped in (source, '/* ' + source + ' */', repr(source), chr(96) + source + chr(96)):
                self.refuse(wrapped, 'contract.txt')

    def test_ambient_parser_budget_and_invalid_type_grant_no_partial_exemption(self):
        for expression in (
            'Namespace.Optional<Namespace.String,,Namespace.Other>',
            'Namespace.Optional<>',
            'Namespace.String Namespace.Other',
            'Namespace.Optional<' * 33 + 'Namespace.String' + '>' * 33,
            'Namespace.Optional<' + ' ' * 8192 + 'Namespace.String>',
        ):
            source = 'export declare const Schema: Namespace.Object<{progressToken: ' + expression + ';}>;'
            self.refuse(source, 'contract.txt')


    def test_ambient_owner_budget_includes_declaration_header(self):
        source = 'export declare const ' + 'S' * 8192 + ': Namespace.Object<{progressToken: Namespace.Optional<Namespace.String>;}>;'
        self.refuse(source, 'contract.txt')


    def test_required_configuration_references_keep_diagnostics_out_of_values(self):
        uri = 'SERVICE_DB_URL: postgresql://${DB_USER:-app}:${DB_PASSWORD:?database password is required}@db:5432/app'
        for path in ('contract.md', 'contract.txt', 'compose.yml'):
            self.accept(uri, path)
            self.accept('SERVICE_TOKEN: ${SERVICE_TOKEN:?service token is required}', path)

    def test_required_diagnostics_and_defaults_cannot_hide_opaque_values(self):
        uri = 'SERVICE_DB_URL: postgresql://${DB_USER:-app}:${DB_PASSWORD:?MESSAGE}@db:5432/app'
        for message in (opaque(), 'password=' + opaque()):
            self.refuse(uri.replace('MESSAGE', message), 'contract.md')
            self.refuse('SERVICE_TOKEN: ${SERVICE_TOKEN:?' + message + '}', 'contract.md')
        self.refuse(uri.replace(':?MESSAGE', ':-' + opaque()), 'contract.md')
        self.refuse(uri.replace('${DB_PASSWORD:?MESSAGE}', opaque()), 'contract.md')
        self.refuse(uri.replace(':?MESSAGE', ':?${NESTED}'), 'contract.md')


    def test_resolver_import_walk_accepts_unrelated_global_and_nonlocal_statements(self):
        prefix = 'from core.secrets import resolve_secret\n'
        suffix = 'token = resolve_secret("SERVICE_TOKEN")\n'
        for declarations in (
            'def count():\n    global counter\n',
            'def owner():\n    counter = None\n    def count():\n        nonlocal counter\n',
        ):
            self.accept(prefix + declarations + suffix, 'entry.py')

    def test_resolver_global_shadow_and_literal_origins_stay_refused(self):
        source = 'from core.secrets import resolve_secret\ndef count():\n    global resolve_secret\n'
        self.refuse(source + 'token = resolve_secret("SERVICE_TOKEN")\n', 'entry.py')
        self.refuse('from core.secrets import resolve_secret\ndef count():\n    global counter\ntoken = ' + repr(opaque()) + '\n', 'entry.py')


if __name__ == '__main__':
    unittest.main()
