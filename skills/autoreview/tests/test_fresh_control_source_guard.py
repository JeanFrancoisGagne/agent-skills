"""Type declarations, sibling copies and marked fixtures retain secret checks."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('fresh_control_guard_under_test', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def field(key, value, separator=': '):
    return key + separator + value


def opaque_value():
    return 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'


def reference_source():
    return ('const state = lookup(request);\n'
            'const { selectedCandidate } = state;\n'
            'let { result, method } = state;\n'
            'method = choose(request);\n'
            'consume({ ' + field('token', 'selectedCandidate') + ' });\n')


class FreshControlGuardTests(unittest.TestCase):
    def accept(self, source, relative='entry.ts'):
        GUARD.require_safe_source('file source', relative, source)

    def refuse(self, source, relative='entry.ts'):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', relative, source)

    def test_type_only_object_members(self):
        member = field('deviceToken', 'DeviceAuthToken | null;')
        sources = (
            'export type Device = Other & {\n  ' + member + '\n};\n',
            'type Device = { nested: Array<{ ' + member + ' }>; };\n',
            'type Device = { ' + field('deviceToken', 'string;') + ' };\n',
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                self.accept(source)

    def test_type_members_keep_runtime_and_literal_refusals(self):
        member = field('deviceToken', repr(opaque_value()))
        sources = (
            'const value = { ' + member + ' };',
            'type Device = { ' + member + '; };',
            'type Device = { ' + field('deviceToken', 'DeviceAuthToken') + ' }; ' + field('password', repr(opaque_value()), ' = '),
            'type Device = { ' + field('deviceToken', 'DeviceAuthToken') + ' + ' + repr(opaque_value()) + '; };',
            'const value = "type Device = { ' + field('deviceToken', 'DeviceAuthToken') + '; };";\n' + field('password', repr(opaque_value()), ' = '),
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                self.refuse(source)
        self.refuse('type Device = { ' + field('deviceToken', 'DeviceAuthToken | null;') + ' };', 'entry.js')

    def test_mutable_sibling_copy_does_not_change_immutable_reference(self):
        self.accept(reference_source())

    def test_call_argument_sibling_without_write(self):
        source = reference_source().replace('let { result, method } = state;',
            'const { result, method } = classify({ value: state });')
        self.accept(source)

    def test_sibling_copy_keeps_member_mutation_and_origin_refusals(self):
        source = reference_source()
        payload = repr(opaque_value())
        additions = (
            'result.member = ' + payload + ';',
            'Object.assign(result, { member: ' + payload + ' });',
            'state.selectedCandidate = ' + payload + ';',
            'const alias = state; alias.selectedCandidate = ' + payload + ';',
        )
        for index, addition in enumerate(additions):
            with self.subTest(index=index):
                self.refuse(source + addition)
        self.refuse(source.replace('lookup(request)', '{ selectedCandidate: ' + payload + ' }'))
        self.refuse(source.replace('selectedCandidate }', 'selectedCandidate = lookup(request) }'))
        self.refuse(source.replace('let {', 'var {'))
        self.refuse(source.replace('let { result, method } = state;', 'const { result, method } = classify({ value: state });') + additions[0])

    def test_write_values_keep_indirect_literal_and_bound_refusals(self):
        source = reference_source()
        sample = repr(opaque_value())
        additions = (
            'const bytes = ' + sample + '; result.member = bytes;',
            'function provide() { return ' + sample + '; } result.member = provide();',
            'const provide = () => ' + sample + '; result.member = provide();',
            'function provide(value = ' + sample + ') { return value; } result.member = provide();',
            'const bytes = String.fromCharCode(65, 55, 102, 57); result.member = bytes;',
            'result[choose(request)] = lookup(request);',
        )
        for index, addition in enumerate(additions):
            with self.subTest(index=index):
                self.refuse(source + addition)
        declarations = ['const value' + str(index) + ' = value' + str(index + 1) + ';' for index in range(33)]
        self.refuse(source + '\n'.join(declarations) + 'result.member = value0;')

    def test_local_class_write_origin_stays_refused(self):
        source = ('class Provider { get() { return ' + repr(opaque_value()) + '; } }\n'
            'const provider = new Provider();\nconst state = lookup(request);\n'
            'const alias = state; alias.selectedCandidate = provider.get();\n'
            'consume({ ' + field('token', 'state.selectedCandidate') + ' });')
        self.refuse(source)

    def test_role_marked_fixture_literals(self):
        for key in ('token', 'password', 'controlToken'):
            with self.subTest(key=key):
                self.accept('const fixture = { ' + field(key, repr('suspension-test-' + ('token' if key == 'controlToken' else key))) + ' };')

    def test_marked_fixture_keeps_credential_refusals(self):
        marker = repr('suspension-test-token')
        sample = repr(opaque_value())
        sources = (
            'const fixture = { ' + field('token', marker + ' + ' + sample) + ' };',
            'const fixture = { ' + field('token', marker) + ', ' + field('password', sample) + ' };',
            'const fixture = { ' + field('token', repr('suspension-test-token-' + opaque_value())) + ' };',
            'const fixture = { ' + field('apiKey', marker) + ' };',
            'const fixture = { ' + field('token', repr(opaque_value() + '-test-token')) + ' };',
            'const fixture = { ' + field('token', repr('suspension-token')) + ' };',
            'const fixture = { ' + field('token', marker) + ' }; const url = ' + repr('postgres://' + 'reader:' + opaque_value() + '@host/db') + ';',
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                self.refuse(source)


if __name__ == '__main__':
    unittest.main()
