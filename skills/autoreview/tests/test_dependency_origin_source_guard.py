"""Public reference branches preserve literal credential refusal."""
import importlib.util
from pathlib import Path
import unittest
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('dependency_guard', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def field(key, value, sep=': '):
    return key + sep + value


def opaque():
    return 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'


class DependencyOriginGuardTests(unittest.TestCase):
    def accept(self, source):
        GUARD.require_safe_source('file source', 'entry.ts', source)

    def refuse(self, source):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', 'entry.ts', source)

    def test_nullable_conditional_references(self):
        source = '\n'.join((
            'const resolvedCredentials = lookup(input);',
            'const useStoredDeviceAuth = condition;',
            'const ' + field('token', 'useStoredDeviceAuth ? undefined : resolvedCredentials.token', ' = ') + ';',
        ))
        self.accept(source)

    def test_conditional_branches_keep_literal_refusal(self):
        for value in (repr(opaque()), 'String.fromCharCode(65,55,102,57)'):
            with self.subTest(value_kind=value.startswith('String')):
                self.refuse('\n'.join((
                    'const resolvedCredentials = lookup(input);',
                    'const useStoredDeviceAuth = condition;',
                    'const ' + field('token', 'useStoredDeviceAuth ? undefined : ' + value, ' = ') + ';',
                )))

    def test_typeof_selector_reference(self):
        self.accept('\n'.join((
            'const testState = lookup(input);',
            'const credentialCandidate = typeof testState.gatewayAuth === "string" ? testState.gatewayAuth : undefined;',
            'consume({' + field('token', 'credentialCandidate') + '});',
        )))

    def test_typeof_selector_keeps_literal_branches(self):
        self.refuse('\n'.join((
            'const testState = lookup(input);',
            'const credentialCandidate = typeof testState.gatewayAuth === "string" ? ' + repr(opaque()) + ' : undefined;',
            'consume({' + field('token', 'credentialCandidate') + '});',
        )))

    def test_boolean_reason_comparison_is_not_a_credential(self):
        self.accept('\n'.join((
            'function verdict(params): { canRetryWithDeviceToken: boolean } {',
            '  const ' + field('canRetryWithDeviceToken', '\n    params.failedAuth.reason === "token_mismatch" &&\n    params.hasDeviceIdentity &&\n    !params.connectAuth?.deviceToken', ' = ') + ';',
            '  switch (params.failedAuth.reason) { case "token_mismatch": break; }',
            '  return {canRetryWithDeviceToken};',
            '}',
        )))

    def test_boolean_name_keeps_actual_credential_refusal(self):
        for source in (
            'const ' + field('canRetryWithDeviceToken', repr(opaque()), ' = ') + ';',
            '\n'.join((
                'function verdict(params): { canRetryWithDeviceToken: boolean } {',
                '  const ' + field('canRetryWithDeviceToken', 'params.token === ' + repr(opaque()), ' = ') + ';',
                '  consume({' + field('token', 'canRetryWithDeviceToken') + '});',
                '  return {canRetryWithDeviceToken};',
                '}',
            )),
        ):
            self.refuse(source)

    def test_declared_const_discriminator_names_its_binding(self):
        self.accept('\n'.join((
            'const sharedGatewayAuthIssuer = enabled ? {kind: "shared-gateway-auth" as const, generation: current} : undefined;',
            'const issuedDeviceGrant = lookup({issuer: sharedGatewayAuthIssuer});',
            'consume({' + field('deviceToken', 'issuedDeviceGrant') + '});',
        )))

    def test_const_discriminator_keeps_other_literals_refused(self):
        base = '\n'.join((
            'const sharedGatewayAuthIssuer = enabled ? {kind: VALUE as const, generation: current} : undefined;',
            'const issuedDeviceGrant = lookup({issuer: sharedGatewayAuthIssuer});',
            'consume({' + field('deviceToken', 'issuedDeviceGrant') + '});',
        ))
        for value in (repr(opaque()), repr('actual-password'), repr('shared-gateway-auth') + ' + ' + repr(opaque())):
            with self.subTest(value_kind=value.startswith("'shared")):
                self.refuse(base.replace('VALUE', value))

    def test_ternary_labels_keep_object_credentials_refused(self):
        self.accept('function kind(input) { return input ? "password" : input.value; }')
        self.refuse('function kind(input) { return input ? {' + field('password', repr(opaque())) + '} : input.value; }')

    def test_exact_counted_fixture_and_numeric_suffix_boundary(self):
        self.accept('consume({' + field('token', repr('test-gateway-token-1234567890')) + '});')
        for suffix in ('1234567891', '1234567890x', opaque()):
            self.refuse('consume({' + field('token', repr('test-gateway-token-' + suffix)) + '});')

    def test_selected_member_ignores_sibling_metadata(self):
        self.accept('\n'.join((
            'const credentialSource = {secretValue: supplied};',
            'credentialSource.rootPath = "ordinary-root";',
            'consume({' + field('token', 'credentialSource.secretValue') + '});',
        )))

    def test_selected_member_retains_direct_alias_and_computed_writes(self):
        for write in (
            'credentialSource.secretValue = ' + repr(opaque()) + ';',
            'const credentialAlias = credentialSource; credentialAlias.secretValue = ' + repr(opaque()) + ';',
            'const credentialAlias: Shape = credentialSource; credentialAlias.secretValue = ' + repr(opaque()) + ';',
            'const credentialAlias = identity(credentialSource); credentialAlias.secretValue = ' + repr(opaque()) + ';',
            'credentialSource[selector] = ' + repr(opaque()) + ';',
            'Object.assign(credentialSource, {secretValue: ' + repr(opaque()) + '});',
            'Reflect.set(credentialSource, selector, ' + repr(opaque()) + ');',
        ):
            with self.subTest(write_kind=write.split(' ', 1)[0]):
                self.refuse('\n'.join(('const credentialSource = lookup(input);', write,
                                       'consume({' + field('token', 'credentialSource.secretValue') + '});')))

    def test_inline_type_assertion_preserves_actual_value(self):
        self.accept('\n'.join((
            'const testState = lookup(input);',
            'const credentialCandidate = typeof (testState.gatewayAuth as { token?: unknown } | undefined)?.token === "string" ? ((testState.gatewayAuth as { token?: string }).token ?? undefined) : undefined;',
            'consume({' + field('token', 'credentialCandidate') + '});',
        )))
        self.refuse('\n'.join((
            'const credentialCandidate = ' + repr(opaque()) + ' as { token?: string };',
            'consume({' + field('token', 'credentialCandidate') + '});',
        )))

    def test_credential_uri_refusal_is_unconditional(self):
        source = 'const credentialSource = {kind: "shared-gateway-auth" as const, url: "postgres://reader:' + opaque() + '@example.invalid/db"};'
        self.refuse(source)

    def test_nullable_selected_members_keep_ancestor_literals(self):
        self.accept('\n'.join(('const incomingSource = lookup(input);',
                               'const credentialSource = incomingSource ?? (enabled ? {} as Shape | undefined : lookup(otherInput));',
                               'consume({' + field('token', 'credentialSource.secretValue') + '});')))
        self.refuse('\n'.join(('const incomingSource = lookup(input);',
                               'const credentialSource = incomingSource ?? {secretValue: ' + repr(opaque()) + '};',
                               'consume({' + field('token', 'credentialSource.secretValue') + '});')))

    def test_origin_expansion_bound_still_refuses_long_value_chains(self):
        declarations = ['const credentialLink0 = lookup(input);']
        declarations.extend('const credentialLink' + str(i) + ' = credentialLink' + str(i - 1) + ';' for i in range(1, 35))
        declarations.append('consume({' + field('token', 'credentialLink34') + '});')
        self.refuse('\n'.join(declarations))

    def test_scope_projection_does_not_rebind_public_destructuring_keys(self):
        self.accept('\n'.join((
            'function unrelated(params) { const {opts, context} = params; return context; }',
            'function caller(opts) { const credentialSource = lookup(opts);',
            'const useStoredDeviceAuth = opts.useStoredDeviceAuth;',
            'const ' + field('token', 'useStoredDeviceAuth ? undefined : credentialSource.secretValue', ' = ') + ';',
            '}',
        )))

    def test_empty_reference_leaves_do_not_spend_value_expansions(self):
        values = ', '.join('inputReference' + str(i) + '.value' for i in range(33))
        self.accept('const credentialSource = lookup({' + values + '}); consume({' + field('token', 'credentialSource') + '});')

    def test_declared_parameter_references_are_bound(self):
        self.accept('function caller(credentialInput) { consume({' + field('token', 'credentialInput.token') + '}); }')
        self.refuse('consume({' + field('token', 'credentialInput.token') + '});')

    def test_parameter_defaults_and_writes_keep_literal_refusal(self):
        for head in (
            'function caller(credentialInput = {token: ' + repr(opaque()) + '}) {',
            'function caller(credentialInput) { credentialInput.token = ' + repr(opaque()) + ';',
        ):
            self.refuse(head + ' consume({' + field('token', 'credentialInput.token') + '}); }')

    def test_named_conditional_selectors_cannot_assemble_credentials(self):
        branches = '(welcomeEnabled ? "welcome" : supplied) + (winterEnabled ? "winter" : supplied)'
        self.refuse('const credentialCandidate = ' + branches + '; consume({' + field('token', 'credentialCandidate') + '});')
        self.refuse('const welcomeSource = welcomeEnabled ? "welcome" : supplied; const winterSource = winterEnabled ? "winter" : supplied; const credentialCandidate = welcomeSource + winterSource; consume({' + field('token', 'credentialCandidate') + '});')


    def test_named_selector_object_fields_cannot_assemble_credentials(self):
        declarations = 'const orchardSource = orchardEnabled ? "orchard" : supplied; const falconSource = falconEnabled ? "falcon" : supplied; '
        routes = (
            'const labels = {orchardSource, falconSource}; const candidate = labels.orchardSource + labels.falconSource;',
            'const labels = {orchardSource: orchardSource, falconSource: falconSource}; const candidate = labels.orchardSource + labels.falconSource;',
            'const labels = {orchardSource, falconSource}; const alias = labels; const candidate = alias.orchardSource + alias.falconSource;',
            'const labels = {orchardSource, falconSource}; const {orchardSource: first, falconSource: second} = labels; const candidate = first + second;',
            'function labels() { return {orchardSource, falconSource}; } const candidate = labels().orchardSource + labels().falconSource;',
            'const labels = {orchardSource, falconSource}; const candidate = labels["orchardSource"] + labels["falconSource"];',
        )
        for index, route in enumerate(routes):
            with self.subTest(route=index):
                self.refuse(declarations + route + ' consume({' + field('token', 'candidate') + '});')
        collisions = 'function unrelated() { const orchardSource = other; const falconSource = another; return {orchardSource, falconSource}; } '
        self.refuse(collisions + declarations + routes[0] + ' consume({' + field('token', 'candidate') + '});')


    def test_short_declared_alias_preserves_literal_refusal(self):
        for name in ('v', 'candidate', 'leaf'):
            self.refuse('const ' + name + ' = ' + repr(opaque()) + '; consume({' + field('token', name) + '});')
        self.accept('function caller(auth) { consume({' + field('token', 'auth') + '}); }')


    def test_named_selector_parameter_fields_keep_literal_origins(self):
        declarations = 'const orchardSource = orchardEnabled ? "orchard" : supplied; const falconSource = falconEnabled ? "falcon" : supplied; const labels = {orchardSource, falconSource}; '
        for callable in (
            'function copy({orchardSource: first, falconSource: second}) { return first + second; }',
            'const copy = ({orchardSource: first, falconSource: second}) => first + second;',
        ):
            self.refuse(declarations + callable + ' const candidate = copy(labels); consume({' + field('token', 'candidate') + '});')


    def test_named_metadata_field_forwarding_keeps_literal_origins(self):
        source = 'function make(input) { const orchardSource = orchardUrl ? "orchard" : supplied; return {orchardSource}; } function forward(input) { return external({orchardSource: input.orchardSource}); } const state = make(supplied); const auth = forward(state); consume({' + field('token', 'auth.token') + '});'
        self.accept(source)
        nullable = 'function make(opts) { const cliUrlOverride = trim(opts.url); const envUrlOverride = trim(env.URL); const urlOverrideSource = cliUrlOverride ? \"cli\" : envUrlOverride ? \"env\" : undefined; return {urlOverrideSource}; } function forward(context) { return external({urlOverrideSource: context.urlOverrideSource}); } const context = make(opts); const resolvedCredentials = forward(context); const ' + field('token', 'condition ? undefined : resolvedCredentials.token', ' = ') + ';'
        self.accept(nullable)
        self.refuse('const orchardSource = orchardEnabled ? "orchard" : supplied; const falconSource = falconEnabled ? "falcon" : supplied; const input = {orchardSource, falconSource}; const labels = {orchardSource: input.orchardSource, falconSource: input.falconSource}; const candidate = labels.orchardSource + labels.falconSource; consume({' + field('token', 'candidate') + '});')

    def test_named_metadata_controls_and_field_aliases_keep_origins(self):
        source = 'function make(opts) { const cliUrlOverride = trim(opts.url); const envUrlOverride = trim(env.URL); const urlOverrideSource = cliUrlOverride ? "cli" : envUrlOverride ? "env" : undefined; return {urlOverrideSource}; } function forward(context) { const eligible = !context.urlOverrideSource && context.urlOverrideSource !== "cli"; return external({urlSource: context.urlOverrideSource}); } const context = make(opts); const resolvedCredentials = forward(context); const ' + field('token', 'condition ? undefined : resolvedCredentials.token', ' = ') + ';'
        self.accept(source)
        declarations = 'const orchardSource = orchardEnabled ? "orchard" : supplied; const falconSource = falconEnabled ? "falcon" : supplied; const input = {orchardSource, falconSource}; '
        self.refuse(declarations + 'const labels = {first: input.orchardSource, second: input.falconSource}; const candidate = labels.first + labels.second; consume({' + field('token', 'candidate') + '});')
        self.refuse(declarations + 'const one = {first: input.orchardSource}; const two = {second: one.first}; const candidate = two.second + input.falconSource; consume({' + field('token', 'candidate') + '});')

    def test_reference_exemptions_require_actual_code(self):
        value = opaque()
        self.refuse('// ' + field('password', value + ' || runtimePassword', ' = '))
        self.refuse('/* ' + field('password', value + ' || runtimePassword', ' = ') + ' */')
        self.refuse('const diagnostic = ' + repr(field('password', value + ' || runtimePassword', ' = ')) + ';')
        self.accept('const ' + field('password', 'configuredPassword || runtimePassword', ' = ') + ';')

    def test_role_mode_member_literals_cannot_feed_credentials(self):
        for member in ('role', 'mode'):
            self.refuse('function unwrap(input) { return input.' + member + '; } const first = {' + member + ': "orchard"}; const second = {' + member + ': "falcon"}; const candidate = unwrap(first) + unwrap(second); consume({' + field('token', 'candidate') + '});')
            self.accept('const input = {' + member + ': "operator", credentials: supplied}; consume({' + field('token', 'input.credentials.token') + '});')

    def test_selector_copy_into_credential_fields_is_refused(self):
        for key in ('token', 'password', 'apiKey'):
            self.refuse('const orchardSource = orchardEnabled ? "orchard" : supplied; consume({' + field(key, 'orchardSource') + '});')

    def test_grouped_typed_member_preserves_selected_value(self):
        setup = 'const state = lookup(input); state.auth = {mode: "token", token: "test-token-1234567890"}; '
        selected = 'const credentialCandidate = typeof (state.auth as { token?: unknown } | undefined)?.token === "string" ? ((state.auth as { token?: string }).token ?? undefined) : undefined; consume({' + field('token', 'credentialCandidate') + '});'
        self.accept(setup + selected)
        self.refuse(setup + 'state.auth.token = ' + repr(opaque()) + '; ' + selected)
        for target in ('(state.auth).token', '(state.auth as {token: string}).token'):
            self.refuse(setup + target + ' = ' + repr(opaque()) + '; ' + selected)
        self.refuse('function unwrap(value) { return value.role; } const first = {role: "orchard"}; const second = {role: "falcon"}; const candidate = unwrap (first).role + unwrap (second).role; consume({' + field('token', 'candidate') + '});')

    def test_selector_ternary_colons_are_not_object_keys(self):
        declarations = 'const orchardSource = orchardEnabled ? "orchard" : supplied; const falconSource = falconEnabled ? "falcon" : supplied; '
        for route in (
            'const candidate = (enabled ? orchardSource : supplied) + (enabled ? falconSource : supplied);',
            'const labels = {first: enabled ? orchardSource : supplied, second: enabled ? falconSource : supplied}; const candidate = labels.first + labels.second;',
        ):
            self.refuse(declarations + route + ' consume({' + field('token', 'candidate') + '});')

    def test_named_type_asserted_writes_preserve_selected_credential(self):
        setup = 'const state = lookup(input); state.auth = {mode: "operator", value: supplied}; '
        for assertion in ('as Auth', 'as Domain.Auth', 'as Auth | undefined', 'satisfies Auth', 'satisfies Domain.Auth | undefined'):
            with self.subTest(assertion=assertion):
                self.refuse(setup + '(state.auth ' + assertion + ').value = ' + repr(opaque()) + '; consume({' + field('token', 'state.auth.value') + '});')
                self.accept(setup + '(state.auth ' + assertion + ').value = supplied; consume({' + field('token', 'state.auth.value') + '});')

    def test_nested_grouped_writes_keep_selected_credential_origins(self):
        setup = 'const state = lookup(input); state.auth = {mode: "operator", value: supplied}; '
        for target in ('((state.auth)).value', '( (state.auth) ).value', '((state).auth).value', '(((state.auth as Auth))).value'):
            with self.subTest(target=target):
                self.refuse(setup + target + ' = ' + repr(opaque()) + '; consume({' + field('token', 'state.auth.value') + '});')
                self.accept(setup + target + ' = supplied; consume({' + field('token', 'state.auth.value') + '});')

    def test_compact_ternary_branches_keep_runtime_value_roots(self):
        declarations = 'const orchardSource=orchardEnabled?"orchard":supplied; const falconSource=falconEnabled?"falcon":supplied; '
        for route in (
            'const candidate=(enabled?orchardSource:supplied)+(enabled?falconSource:supplied); consume({token:candidate});',
            'const labels={first:enabled?orchardSource:supplied,second:enabled?falconSource:supplied}; const candidate=labels.first+labels.second; consume({token:candidate});',
            'const ' + field('token', 'enabled?orchardSource:supplied', '=') + ';',
        ):
            self.refuse(declarations + route)
        for selection in ('input.token', 'input?.token'):
            self.accept('const input=lookup(supplied); const candidate=enabled?' + selection + ':undefined; consume({token:candidate});')

    def test_unresolved_grouped_writes_keep_credential_refusal(self):
        setup = 'const state = lookup(input); state.auth = {value: supplied}; '
        targets = ('(enabled ? state.auth : other).value', 'identity(state.auth).value', '(state.auth)[selected]', '(' * 40 + 'state.auth' + ')' * 40 + '.value')
        for index, target in enumerate(targets):
            with self.subTest(target_kind=index):
                self.refuse(setup + target + ' = ' + repr(opaque()) + '; consume({' + field('token', 'state.auth.value') + '});')

    def test_compact_conditional_writes_keep_value_and_mutation_roots(self):
        setup = 'const state=lookup(input); state.auth={value:supplied}; '
        routes = (
            'enabled?state.auth.value=' + repr(opaque()) + ':unused;',
            'enabled?Object.assign(state.auth,{value:' + repr(opaque()) + '}):unused;',
            'enabled?Reflect.set(state.auth,"value",' + repr(opaque()) + '):unused;',
        )
        for index, route in enumerate(routes):
            with self.subTest(route=index):
                self.refuse(setup + route + ' consume({token:state.auth.value});')
        self.refuse('let candidate=lookup(input); enabled?candidate=' + repr(opaque()) + ':unused; consume({token:candidate});')

    def test_later_alias_assignments_preserve_selected_mutations(self):
        setup = 'const state = lookup(input); state.auth = {value: supplied}; '
        routes = (
            'let alias; alias = state; alias.auth.value = ',
            'var alias; alias = state.auth; alias.value = ',
            'let alias: Shape; alias = (state.auth as Auth); alias.value = ',
            'let first; let alias; first = state.auth; alias = first; alias.value = ',
            'let alias; alias = state.auth; alias = state; alias.auth.value = ',
        )
        for index, route in enumerate(routes):
            with self.subTest(route=index):
                self.refuse(setup + route + repr(opaque()) + '; consume({' + field('token', 'state.auth.value') + '});')
        self.accept(setup + 'let alias; alias = state.auth; alias.mode = "operator"; consume({' + field('token', 'state.auth.value') + '});')

    def test_unproved_later_aliases_keep_grouped_writes_refused(self):
        setup = 'const state = lookup(input); state.auth = {value: supplied}; let alias; '
        for value in ('identity(state.auth)', '(enabled ? state.auth : other)'):
            self.refuse(setup + 'alias = ' + value + '; ((alias)).value = ' + repr(opaque()) + '; consume({' + field('token', 'state.auth.value') + '});')

    def test_repeated_late_alias_scan_keeps_credential_refusal(self):
        source = 'const state = lookup(input); let alias; alias = state; alias.value = ' + repr(opaque()) + '; consume({' + field('token', 'state.value') + '});'
        for _ in range(2):
            self.refuse(source)


    def test_scoped_ternary_bindings_keep_local_credential_origins(self):
        outer = 'function unrelated() { const candidate = supplied; } '
        for branch in ('enabled ? candidate : undefined', 'enabled?candidate:undefined', 'enabled ? (ready ? candidate : undefined) : undefined'):
            source = outer + 'function caller(enabled, ready) { const candidate = VALUE; const ' + field('token', branch, ' = ') + '; }'
            self.refuse(source.replace('VALUE', repr(opaque())))
            self.accept(source.replace('VALUE', 'supplied'))
        self.accept(outer + 'function caller(enabled) { const candidate = supplied; consume({candidate: enabled}); const ' + field('token', 'candidate', ' = ') + '; }')

    def test_parameter_annotations_keep_runtime_credentials_separate(self):
        self.accept('function maskToken(token: string): string { return token; }')
        self.accept('function maskToken(token: string): string { return token === "***" ? token : input; }')
        self.refuse('function maskToken(token: string): string { const ' + field('token', repr(opaque()), ' = ') + '; return token; }')

    def test_mutable_regex_result_is_not_proven_boolean(self):
        self.refuse('const check = /abc/u; const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_regex_result_proof_keeps_changed_methods_and_literals_refused(self):
        for setup in (
            'const check = {test: () => ' + repr(opaque()) + '};',
            'const check = /abc/u; check.test = () => ' + repr(opaque()) + ';',
            'const check = /abc/u; const alias = check; alias.test = () => ' + repr(opaque()) + ';',
            'const check = /abc/u; check["test"] = () => ' + repr(opaque()) + ';',
            'RegExp.prototype.test = () => ' + repr(opaque()) + '; const check = /abc/u;',
        ):
            self.refuse(setup + ' const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')
        self.refuse('const check = /abc/u; const ' + field('token', 'left !== right || check.test(' + repr(opaque()) + ')', ' = ') + ';')
        for op in ('||', '&&'):
            source = 'function unrelated(){const candidate=supplied;} function caller(enabled){const candidate=' + repr(opaque()) + '; const ' + field('token', 'enabled ' + op + ' candidate', ' = ') + ';}'
            self.refuse(source)

    def test_readonly_query_does_not_prove_mutable_regex_result(self):
        setup = 'const prototype = Object.getPrototypeOf(input); consume(prototype === Object.prototype); const check = /abc/u; '
        self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_prototype_alias_and_computed_writes_keep_credentials_refused(self):
        for mutation in ('prototype.test', 'prototype["test"]', 'alias[method]'):
            setup = 'const prototype = Object.getPrototypeOf(/abc/u); const alias = prototype; const method = "test"; ' + mutation + ' = () => ' + repr(opaque()) + '; const check = /abc/u; '
            self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_array_type_does_not_prove_mutable_regex_result(self):
        setup = 'const values: string[] = []; const out = {}; out[key] = input; const check = /abc/u; '
        self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_computed_prototype_writes_keep_credentials_refused(self):
        for mutation in ('RegExp["prototype"]["test"]', 'RegExp[prototypeName][method]'):
            setup = 'const prototypeName = "prototype"; const method = "test"; ' + mutation + ' = () => ' + repr(opaque()) + '; const check = /abc/u; '
            self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_selected_members_refuse_prototype_value_writes(self):
        for write in (
            'state.__proto__ = {value: ' + repr(opaque()) + '};',
            'state.__proto__.value = ' + repr(opaque()) + ';',
            'const alias = state; alias.__proto__ = {value: ' + repr(opaque()) + '};',
            'state["__proto__"] = {value: ' + repr(opaque()) + '};',
            'Object.setPrototypeOf(state, {value: ' + repr(opaque()) + '});',
        ):
            with self.subTest(write_kind=write.split(' ', 1)[0]):
                self.refuse('const state = {}; ' + write + ' consume({' + field('token', 'state.value') + '});')
        for key in ('__proto__', repr('__proto__')):
            self.refuse('const state = {' + key + ': {value: ' + repr(opaque()) + '}}; consume({' + field('token', 'state.value') + '});')

    def test_selected_members_refuse_shared_and_constructor_prototype_writes(self):
        for write in (
            'state.constructor.prototype.value = ' + repr(opaque()) + ';',
            'const alias = state; alias.constructor.prototype.value = ' + repr(opaque()) + ';',
            'Object.prototype.value = ' + repr(opaque()) + ';',
            'Object["prototype"].value = ' + repr(opaque()) + ';',
            'const prototype = Object.prototype; prototype.value = ' + repr(opaque()) + ';',
        ):
            with self.subTest(write_kind=write.split(' ', 1)[0]):
                self.refuse('const state = {}; ' + write + ' consume({' + field('token', 'state.value') + '});')

    def test_prototype_discovery_retains_computed_and_returned_origins(self):
        declarations = (
            'const inherited = Object["getPrototypeOf"]({});',
            "const inherited = Reflect['getPrototypeOf']({});",
            'const Native = Object; const get = Native["getPrototypeOf"]; const inherited = get({});',
            'const get = Object.getPrototypeOf; const inherited = get.call(Object, {});',
            'const inherited = Object.getPrototypeOf.call(Object, {});',
            'const other = {}; const inherited = other["constructor"]["prototype"];',
            'function discover() { return Object["getPrototypeOf"]({}); } const inherited = discover();',
            'const Native = Reflect; const inherited = Native["getPrototypeOf"]({});',
            'const key = query(input); const inherited = Object[key]({});',
        )
        for index, declaration in enumerate(declarations):
            with self.subTest(case=index):
                self.refuse(declaration + ' inherited.value = ' + repr(opaque()) + '; const state = {}; consume({' + field('token', 'state.value') + '});')
        self.refuse('const Native = Object; const state = {}; Native["setPrototypeOf"](state, {value: ' + repr(opaque()) + '}); consume({' + field('token', 'state.value') + '});')
        self.refuse('const inherited = Object.getPrototypeOf({}); function change(value) { value.value = ' + repr(opaque()) + '; } change(inherited); const state = {}; consume({' + field('token', 'state.value') + '});')
        self.refuse('function change(value) { value.value = ' + repr(opaque()) + '; } change(Object["getPrototypeOf"]({})); const state = {}; consume({' + field('token', 'state.value') + '});')

    def test_readonly_computed_query_does_not_prove_mutable_regex_result(self):
        for query in ('Object["getPrototypeOf"](input)', 'Object.getPrototypeOf(input)'):
            setup = 'const prototype = ' + query + '; consume(prototype === Object.prototype); const check = /abc/u; '
            self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_prototype_discovery_refuses_unproved_result_escapes(self):
        prefixes = (
            '(Object["getPrototypeOf"]({})).value = ',
            'const get = Object.getPrototypeOf; [get][0]({}).value = ',
            'const get = Object.getPrototypeOf; const payload = {get}; const inherited = payload.get({}); inherited.value = ',
        )
        for index, prefix in enumerate(prefixes):
            with self.subTest(case=index):
                self.refuse(prefix + repr(opaque()) + '; const state = {}; consume({' + field('token', 'state.value') + '});')

    def test_generic_header_keeps_unproved_result_and_credential_boundaries(self):
        ordinary = 'function identity<T>(value: T): T { return value; } const check = /abc/u; '
        self.refuse(ordinary + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')
        for query in ('Object["getPrototypeOf"](input)', 'Object["getPrototypeOf"]'):
            with self.subTest(query=query):
                source = 'function get<T>(input: T) { return ' + query + '; } const p = get({}); p.value = '
                self.refuse(source + repr(opaque()) + '; const state = {}; consume({' + field('token', 'state.value') + '});')

    def test_conditional_regex_source_retains_credential_literal(self):
        expression = 'enabled ? /' + opaque() + '/.source : supplied'
        self.refuse('const ' + field('token', expression, ' = ') + ';')

    def test_optional_call_keeps_native_forwarding_refusal(self):
        self.refuse('\n'.join((
            'const p = "prototype"; const m = "test";',
            'const hidden = ' + repr(opaque()) + ';',
            'function patch(n) { n[p][m] = () => hidden; }',
            'patch?.(RegExp || fallback); const check = /abc/u;',
            'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
        )))
        self.refuse('\n'.join((
            'const NativeObject = Object; NativeObject.keys?.(input);',
            'const check = /abc/u;',
            'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
        )))

    def test_wrapped_native_namespace_keeps_credential_origin(self):
        for expression in ('RegExp || fallback', 'RegExp ?? fallback', 'condition && RegExp', 'condition ? RegExp : fallback'):
            with self.subTest(expression=expression):
                self.refuse('\n'.join((
                    'const p = "prototype"; const m = "test";',
                    'const hidden = ' + repr(opaque()) + ';',
                    'function patch(n) { n[p][m] = () => hidden; }',
                    'patch(' + expression + '); const check = /abc/u;',
                    'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
                )))

    def test_returned_native_namespace_keeps_credential_origin(self):
        self.refuse('\n'.join((
            'const p = "prototype"; const m = "test";',
            'const hidden = ' + repr(opaque()) + ';',
            'function native() { return RegExp; } const n = native();',
            'n[p][m] = () => hidden;',
            'const check = /abc/u;',
            'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
        )))

    def test_native_namespace_forwarding_keeps_credential_origin(self):
        for namespace in ('RegExp', 'NativeRegex'):
            with self.subTest(namespace=namespace):
                self.refuse('\n'.join((
                    'const p = "prototype"; const m = "test";',
                    'const hidden = ' + repr(opaque()) + ';',
                    'function patch(n) { n[p][m] = () => hidden; }',
                    'const NativeRegex = RegExp;',
                    'patch(' + namespace + ');',
                    'const check = /abc/u;',
                    'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
                )))
        self.refuse('\n'.join((
            'const NativeObject = Object; NativeObject.keys(input);',
            'const check = /abc/u;',
            'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';',
        )))

    def test_multiline_boolean_proof_keeps_credential_operand(self):
        source = 'const candidate = ' + repr(opaque()) + '; const check = /abc/u; const '
        self.refuse(source + field('token', 'candidate\n || check.test(input)', ' = ') + ';')

    def test_mutable_native_result_keeps_assignment_refusal(self):
        self.refuse('const check = /abc/u; const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')
        self.refuse('const FIELD_RE = /abc/u; const shouldRedactAppPassword = redacted !== value || FIELD_RE.test(key);')

    def test_global_namespace_forwarding_keeps_credential_refusal(self):
        setup = '\n'.join((
            'const p = "prototype"; const m = "test";',
            'const hidden = ' + repr(opaque()) + ';',
            'function patch(n) { n[p][m] = () => hidden; }',
            'patch(globalThis.RegExp); const check = /abc/u;',
        ))
        self.refuse(setup + 'const ' + field('token', 'left !== right || check.test(input)', ' = ') + ';')

    def test_global_namespace_selected_member_keeps_credential_refusal(self):
        setup = '\n'.join((
            'const p = "prototype"; const m = "value";',
            'const hidden = ' + repr(opaque()) + ';',
            'function patch(n) { n[p][m] = hidden; }',
            'patch(globalThis.Object || fallback); const state = {};',
        ))
        self.refuse(setup + 'consume({' + field('token', 'state.value') + '});')

    def test_syntactic_boolean_results_preserve_reference_controls(self):
        for expression in ('left !== right || ready === supplied', '!ready || !!supplied', 'left !== right && true', 'enabled ? true : false'):
            with self.subTest(expression=expression):
                self.accept('const ' + field('token', expression, ' = ') + ';')
        self.accept('const NativeObject = Object; NativeObject.keys(input); const state = {value: supplied}; consume({' + field('token', 'state.value') + '});')
        self.accept('consume(() => { const NativeObject = Object; NativeObject.keys(input); }); const state = {value: supplied}; consume({' + field('token', 'state.value') + '});')

    def test_cached_prototype_context_keeps_selected_targets_separate(self):
        source = 'const first = {}; const second = {}; Object.assign(second, {value: supplied});'
        code = GUARD.javascript_binding_code(source)
        self.assertFalse(GUARD.javascript_prototype_writes(source, code, ('first',)))
        self.assertTrue(GUARD.javascript_prototype_writes(source, code, ('second',)))
        self.assertFalse(GUARD.javascript_prototype_writes(source, code, ('first',)))

    def test_nonreference_prototype_receiver_keeps_credential_refusal(self):
        source = 'const hidden = ' + repr(opaque()) + '; const inherited = ({}).constructor.prototype; inherited.value = hidden; const state = {}; state.mode = "operator"; consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_selected_object_requires_own_value_origin(self):
        self.assertIsNone(GUARD.javascript_selected_object_origins("{}", ["value"]))
        self.assertIsNone(GUARD.javascript_selected_object_origins("{nested: {mode: selector}}", ["nested", "value"]))
        self.refuse('const state = {}; state.mode = "operator"; consume({' + field('token', 'state.value') + '});')
        self.accept('const state = {value: supplied, mode: selector}; consume({' + field('token', 'state.value') + '});')
        self.refuse('Object.prototype.value = ' + repr(opaque()) + '; const state = {}; consume({' + field('token', 'state.value') + '});')

    def test_computed_literal_receiver_keeps_credential_refusal(self):
        source = 'const hidden = ' + repr(opaque()) + '; const inherited = {}["constructor"]["prototype"]; inherited.value = hidden; const state = lookup(input); consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_selected_mutable_argument_keeps_credential_refusal(self):
        source = 'const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; } const state = lookup(input); state.mode = "operator"; patch(state); consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_literal_computed_prototype_receiver_keeps_credential_refusal(self):
        source = 'const hidden = ' + repr(opaque()) + '; const inherited = {}["__proto__"]; inherited.value = hidden; const state = {}; state.mode = "operator"; consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_selected_receiver_calls_keep_credential_refusal(self):
        for call in ('state.rewrite()', '(state).rewrite()', 'state["rewrite"]()'):
            with self.subTest(call=call):
                source = 'const hidden = ' + repr(opaque()) + '; const state = lookup(input); state.mode = "operator"; state.rewrite = function() { this.value = hidden; }; ' + call + '; consume({' + field('token', 'state.value') + '});'
                self.refuse(source)

    def test_selected_carrier_calls_keep_credential_refusal(self):
        carriers = (
            ('const carried = {node: state};', 'carried', 'obj.node.value'),
            ('const carried = {node: state}; const {node: alias} = carried;', 'alias', 'obj.value'),
            ('const carried = {node: state}; const copied = {...carried};', 'copied', 'obj.node.value'),
        )
        for declaration, argument, destination in carriers:
            with self.subTest(argument=argument):
                source = 'const hidden = ' + repr(opaque()) + '; function patch(obj) { ' + destination + ' = hidden; } const state = lookup(input); state.mode = "operator"; ' + declaration + ' patch(' + argument + '); consume({' + field('token', 'state.value') + '});'
                self.refuse(source)

    def test_unproved_sibling_metadata_keeps_selected_refusal(self):
        for expression in ('directoryName + "ordinary-root"', 'function() { return supplied; }', '{run: callback}'):
            with self.subTest(expression=expression):
                self.refuse('const state = lookup(input); state.mode = ' + expression + '; consume({' + field('token', 'state.value') + '});')

    def test_selected_template_escapes_keep_credential_refusal(self):
        self.refuse('const hidden = ' + repr(opaque()) + '; function tag(parts, obj) { obj.value = hidden; } const state = lookup(input); state.mode = "operator"; tag`${state}`; consume({' + field('token', 'state.value') + '});')
        self.refuse('const hidden = ' + repr(opaque()) + '; const state = lookup(input); state.mode = "operator"; state.toString = function() { this.value = hidden; return "ok"; }; const text = `${state}`; consume({' + field('token', 'state.value') + '});')

    def test_scoped_selected_template_keeps_credential_refusal(self):
        source = "const state = {value: supplied}; function leak() { const hidden = " + repr(opaque()) + "; function tag(parts, obj) { obj.value = hidden; } const state = lookup(input); state.mode = \"operator\"; tag`${state}`; consume({" + field("token", "state.value") + "}); }"
        self.refuse(source)


    def test_proved_boolean_result_is_not_a_mutable_carrier(self):
        source = 'const state = {value: supplied}; const ready = state.mode !== undefined; consume(ready); consume({' + field('token', 'state.value') + '});'
        self.accept(source)

    def test_scalar_result_keeps_selected_literal_refusal(self):
        source = 'const state = {value: ' + repr(opaque()) + '}; const ready = state.mode !== undefined; consume(ready); consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_unknown_result_stays_a_mutable_carrier(self):
        source = 'const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; } const state = {value: supplied}; const carried = transform(state.mode); patch(carried); consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_scalar_result_does_not_hide_root_argument_escape(self):
        source = 'const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; return false; } const state = {value: supplied}; const ready = patch(state) !== undefined; consume(ready); consume({' + field('token', 'state.value') + '});'
        self.refuse(source)

    def test_code_owned_call_result_keeps_argument_mutation_refusal(self):
        source = 'function run(input) { const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; } function lookup(value) { return value; } const state = lookup(input).state; state.mode = "operator"; patch(state); consume({' + field('token', 'state.value') + '}); }'
        self.refuse(source)

    def test_optional_local_producer_keeps_literal_return_refusal(self):
        source = 'function producer() { return ' + repr(opaque()) + '; } const ' + field('token', 'producer?.()', ' = ') + ';'
        self.refuse(source)

    def test_nonliteral_local_producer_calls_remain_code(self):
        for invocation in ('producer(input)', 'producer?.(input)'):
            with self.subTest(optional='?.' in invocation):
                source = 'function producer(value) { return value; } function run(input) { const ' + field('token', invocation, ' = ') + '; consume({token}); }'
                self.accept(source)

    def test_code_owned_call_result_keeps_scalar_metadata(self):
        source = 'function lookup(value) { return value; } function run(input) { const state = lookup(input).state; state.mode = "operator"; consume({' + field('token', 'state.value') + '}); }'
        self.accept(source)

    def test_typed_local_producer_keeps_literal_return_refusal(self):
        for setup, invocation in (('', 'producer<typeof input>()'), ('', 'producer?.<typeof input>()'), ('const alias = producer; ', 'alias?.<typeof input>()'), ('const holder = {make: producer}; ', 'holder.make?.<typeof input>()')):
            with self.subTest(invocation=invocation):
                source = 'function producer<T>() { return ' + repr(opaque()) + '; } function run(input) { ' + setup + 'const ' + field('token', invocation, ' = ') + '; }'
                self.refuse(source)

    def test_selected_source_alias_keeps_argument_mutation_refusal(self):
        for initializer in ('input.state', 'input?.state'):
            with self.subTest(initializer=initializer):
                source = 'function run(input) { const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; } const state = ' + initializer + '; state.mode = "operator"; patch(state); consume({' + field('token', 'state.value') + '}); }'
                self.refuse(source)

    def test_typed_nonliteral_local_producer_calls_remain_code(self):
        for setup, invocation in (('', 'producer<typeof input>(input)'), ('', 'producer?.<typeof input>(input)'), ('const alias = producer; ', 'alias?.<typeof input>(input)'), ('const holder = {make: producer}; ', 'holder.make?.<typeof input>(input)')):
            with self.subTest(invocation=invocation):
                source = 'function producer<T>(value) { return value; } function run(input) { ' + setup + 'const ' + field('token', invocation, ' = ') + '; consume({token}); }'
                self.accept(source)

    def test_selected_source_alias_keeps_scalar_metadata(self):
        for initializer in ('input.state', 'input?.state', 'lookup<typeof input>(input).state', 'lookup?.<typeof input>(input).state', None):
            with self.subTest(initializer=initializer):
                binding = 'const {state} = input; ' if initializer is None else 'const state = ' + initializer + '; '
                source = 'function lookup<T>(value) { return value; } function run(input) { ' + binding + 'state.mode = "operator"; consume({' + field('token', 'state.value') + '}); }'
                self.accept(source)

    def test_destructured_callee_keeps_typed_literal_return_refusal(self):
        source = 'function producer<T>() { return ' + repr(opaque()) + '; } function run(input) { const holder = {make: producer}; const {make} = holder; const ' + field('token', 'make?.<typeof input>()', ' = ') + '; }'
        self.refuse(source)

    def test_destructured_source_alias_keeps_argument_mutation_refusal(self):
        source = 'function run(input) { const hidden = ' + repr(opaque()) + '; function patch(obj) { obj.value = hidden; } const {state} = input; state.mode = "operator"; patch(state); consume({' + field('token', 'state.value') + '}); }'
        self.refuse(source)


    def test_invoked_callee_normalization_keeps_literal_return_refusal(self):
        initializers = ('(producer)', '((producer))', 'input ? producer : producer', '(input ? producer : producer)')
        for initializer in initializers:
            for invocation in ('callee()', 'callee?.()'):
                with self.subTest(initializer=initializer, invocation=invocation):
                    source = f'function producer() {{ return "{opaque()}"; }} function run(input) {{ const callee = {initializer}; const token = {invocation}; }}'
                    self.refuse(source)

    def test_returned_callable_keeps_literal_return_refusal(self):
        bodies = ('const callee = factory(); const token = callee?.();', 'const token = factory?.()();')
        for body in bodies:
            with self.subTest(body=body):
                source = f'function producer() {{ return "{opaque()}"; }} function factory() {{ return producer; }} function run(input) {{ {body} }}'
                self.refuse(source)

    def test_normalized_and_returned_callees_keep_nonliteral_code(self):
        bodies = ('const callee = (producer); const token = callee?.();', 'const callee = ((producer)); const token = callee?.();', 'const callee = input ? producer : producer; const token = callee?.();', 'const callee = (input ? producer : producer); const token = callee?.();', 'const callee = factory(); const token = callee?.();', 'const token = factory?.()();', 'const callee = unused ? producer : producer; const token = callee?.();')
        for body in bodies:
            with self.subTest(body=body):
                source = f'function unused() {{ return "{opaque()}"; }} function producer() {{ return operation(); }} function factory() {{ return producer; }} function run(input) {{ {body} }}'
                self.accept(source)


    def test_invoked_value_operators_keep_literal_return_refusal(self):
        literal = '"' + opaque() + '"'
        for initializer in ('(input, producer)', 'input && producer', 'input || producer', 'input ?? producer'):
            for call in ('callee()', 'callee?.()'):
                source = 'function producer() { return ' + literal + '; } function run(input) { const callee = ' + initializer + '; const token = ' + call + '; }'
                with self.subTest(initializer=initializer, call=call):
                    self.refuse(source)

    def test_returned_formal_callable_keeps_literal_return_refusal(self):
        literal = '"' + opaque() + '"'
        for parameters, returned, argument in (('fn', 'fn', 'producer'), ('fn', 'alias', 'producer'), ('{fn}', 'fn', '{fn: producer}')):
            body = 'const alias = fn; ' if returned == 'alias' else ''
            for call in ('const callee = factory(' + argument + '); const token = callee?.();', 'const token = factory(' + argument + ')();'):
                source = 'function producer() { return ' + literal + '; } function factory(' + parameters + ') { ' + body + 'return ' + returned + '; } function run(input) { ' + call + ' }'
                with self.subTest(parameters=parameters, returned=returned, call=call):
                    self.refuse(source)

    def test_unproved_returned_formals_do_not_reject_direct_runtime_calls(self):
        self.accept('function run(input) { const token = input(); }')
        self.accept('function run(input) { const token = input.handler(); }')
        literal = '"' + opaque() + '"'
        source = 'function unused() { return ' + literal + '; } function producer() { return unknownRuntimeOperation(); } function factory(fn) { return producer; } function run(input) { const token = factory(unused)(); }'
        self.accept(source)


    def test_captured_callback_invocation_keeps_literal_return_refusal(self):
        literal = '"' + opaque() + '"'
        for parameters, argument in (('fn', 'producer'), ('{fn}', '{fn: producer}')):
            source = 'function producer() { return ' + literal + '; } function factory(' + parameters + ') { return fn(); } function run(input) { const token = factory(' + argument + '); }'
            with self.subTest(parameters=parameters):
                self.refuse(source)

    def test_captured_arrow_callback_keeps_literal_return_refusal(self):
        literal = '"' + opaque() + '"'
        for initializer, invocation in (('(fn) => fn', 'factory(producer)()'), ('(fn) => fn()', 'factory(producer)'), ('(fn) => { const alias = fn; return alias; }', 'factory(producer)()')):
            source = 'function producer() { return ' + literal + '; } function run(input) { const factory = ' + initializer + '; const token = ' + invocation + '; }'
            with self.subTest(initializer=initializer):
                self.refuse(source)

    def test_captured_callable_rebinding_keeps_literal_refusal(self):
        declaration = 'function producer() { return operation(); } '
        for replacement, invocation in (
            ('producer = () => ' + repr(opaque()) + '; ', 'producer?.()'),
            ('producer = function () { return ' + repr(opaque()) + '; }; ', 'producer<string>()'),
            ('const replacement = () => ' + repr(opaque()) + '; producer = replacement; ', '(producer)()'),
            ('producer = () => () => ' + repr(opaque()) + '; ', 'producer()()'),
            ('producer = ' + repr(opaque()) + '; ', 'producer'),
        ):
            with self.subTest(invocation=invocation):
                self.refuse(declaration + replacement + 'const ' + field('token', invocation, ' = ') + ';')
        imported = 'import { producer } from "./provider"; producer = () => ' + repr(opaque()) + '; '
        self.refuse(imported + 'const ' + field('token', 'producer?.()', ' = ') + ';')

    def test_nonliteral_captured_callable_rebinding_remains_code(self):
        for declaration in ('function producer() { return operation(); } ', 'import { producer } from "./provider"; '):
            for replacement, invocation in (
                ('producer = () => operation(); ', 'producer?.()'),
                ('const replacement = () => operation(); producer = replacement; ', '(producer)()'),
                ('producer = () => () => operation(); ', 'producer()()'),
            ):
                with self.subTest(invocation=invocation):
                    self.accept(declaration + replacement + 'const ' + field('token', invocation, ' = ') + ';')


    def test_grouped_and_destructured_callable_rebinding_keeps_literal_refusal(self):
        declaration = 'function producer() { return operation(); } '
        for replacement in (
            '(producer) = () => ' + repr(opaque()) + '; ',
            '(producer as Callable) = () => ' + repr(opaque()) + '; ',
            'producer = null; (producer) ??= () => ' + repr(opaque()) + '; ',
            '({producer} = {producer: () => ' + repr(opaque()) + '}); ',
            '[producer] = [() => ' + repr(opaque()) + ']; ',
            '({selected: producer} = {selected: () => ' + repr(opaque()) + '}); ',
        ):
            with self.subTest(shape=replacement.split('=')[0].strip()):
                self.refuse(declaration + replacement + 'const ' + field('token', 'producer?.()', ' = ') + ';')

    def test_grouped_nonliteral_callable_rebinding_remains_code(self):
        declaration = 'function producer() { return operation(); } '
        for replacement in ('(producer) = () => operation(); ', '(producer as Callable) = () => operation(); ', 'producer = null; (producer) ??= () => operation(); '):
            self.accept(declaration + replacement + 'const ' + field('token', 'producer?.()', ' = ') + ';')


    def test_formal_callable_captured_rebindings_keep_literal_refusal(self):
        for replacement, invocation in (
            ('({selected: fn} = {selected: () => ' + repr(opaque()) + '}); ', 'fn?.()'),
            ('[fn] = [() => ' + repr(opaque()) + ']; ', 'fn<string>()'),
            ('(fn) = () => ' + repr(opaque()) + '; ', '(fn)()'),
            ('(fn as Callable) = () => () => ' + repr(opaque()) + '; ', 'fn()()'),
            ('({selected: fn} = {selected: {token: ' + repr(opaque()) + '}}); ', 'fn.token'),
        ):
            with self.subTest(invocation=invocation):
                self.refuse('function caller(fn) { ' + replacement + 'const ' + field('token', invocation, ' = ') + '; }')

    def test_formal_callable_without_literal_rebinding_remains_code(self):
        for replacement, invocation in (
            ('', 'fn?.()'),
            ('(fn) = () => operation(); ', '(fn)()'),
            ('(fn as Callable) = () => () => operation(); ', 'fn()()'),
        ):
            self.accept('function caller(fn) { ' + replacement + 'const ' + field('token', invocation, ' = ') + '; }')

    def test_destructured_code_binding_body_reassignment_keeps_literal_refusal(self):
        for replacement in (
            '({selected: fn} = {selected: () => ' + repr(opaque()) + '}); ',
            '(fn) = () => ' + repr(opaque()) + '; ',
        ):
            self.refuse('function caller(input) { const {fn} = input; ' + replacement + 'const token = fn?.(); }')

    def test_untouched_destructured_code_binding_remains_code(self):
        self.accept('function caller(input) { const {fn} = input; const token = fn?.(); }')

    def test_selected_formal_root_replacements_keep_literal_refusal(self):
        for replacement in (
            '({selected: input} = {selected: {make: () => ' + repr(opaque()) + '}}); ',
            '(input) = {make: () => ' + repr(opaque()) + '}; ',
            '(input as Runtime) = {make: () => ' + repr(opaque()) + '}; ',
            'var {selected: input} = {selected: {make: () => ' + repr(opaque()) + '}}; ',
        ):
            with self.subTest(shape=replacement.split('=')[0].strip()):
                self.refuse('function caller(input) { ' + replacement + 'const token = input.make?.(); }')

    def test_var_destructuring_replacements_keep_literal_refusal(self):
        for head in (
            'function caller(fn) { ',
            'function caller() { function fn() { return operation(); } ',
        ):
            self.refuse(head + 'var {selected: fn} = {selected: () => ' + repr(opaque()) + '}; const token = fn?.(); }')

    def test_selected_formal_untouched_and_owned_replacements_remain_code(self):
        self.accept('function caller(input) { const token = input.make?.(); }')
        for replacement in ('(input) = {make: () => operation()}; ', '(input as Runtime) = {make: () => operation()}; '):
            self.accept('function caller(input) { ' + replacement + 'const token = input.make?.(); }')

    def test_iterator_target_replacements_keep_literal_refusal(self):
        for target, iterable in (
            ('fn', '[() => ' + repr(opaque()) + ']'),
            ('[fn]', '[[() => ' + repr(opaque()) + ']]'),
            ('{selected: fn}', '[{selected: () => ' + repr(opaque()) + '}]'),
        ):
            with self.subTest(target=target):
                self.refuse('function caller(fn) { for (' + target + ' of ' + iterable + ') { const token = fn?.(); } }')

    def test_selected_iterator_target_keeps_literal_refusal(self):
        for opening in ('for (', 'for await ('):
            self.refuse('async function caller(input) { ' + opening + 'input.make of [() => ' + repr(opaque()) + ']) { const token = input.make?.(); } }')

    def test_for_in_target_keeps_captured_key_literal_refusal(self):
        self.refuse('function caller(fn) { for (fn in {[' + repr(opaque()) + ']: true}) { const token = fn; } }')

    def test_unrelated_fresh_iterator_does_not_rebind_runtime_formal(self):
        self.accept('function caller(fn) { for (const item of items) { inspect(item); } const token = fn?.(); }')
        self.accept('function caller(fn) { for (let item in items) { inspect(item); } const token = fn?.(); }')
        self.accept('function caller(fn) { for (const fn of items) { inspect(fn); } const token = fn?.(); }')

    def test_loop_header_keeps_its_literal_callable_binding(self):
        self.refuse('function caller(fn) { for (let fn = () => ' + repr(opaque()) + '; consume({token: fn?.()}); ) { break; } }')

    def test_single_statement_loop_keeps_outer_runtime_formal(self):
        self.accept('function caller(fn, entries) { for (const fn of entries) inspect(fn); const token = fn?.(); }')

    def test_iteration_public_key_does_not_rebind_outer_formal(self):
        self.accept('function caller(fn, entries) { for (var {fn: other} of entries) { inspect(other); } const token = fn?.(); }')

    def test_loop_header_owned_code_and_later_outer_formal_remain_code(self):
        self.accept('function caller(fn) { for (let fn = () => operation(); consume({token: fn?.()}); ) { break; } const token = fn?.(); }')

    def test_semicolon_free_loop_cannot_keep_its_local_callable_after_body(self):
        self.refuse('function caller() { const fn = () => ' + repr(opaque()) + '; for (let fn = () => operation(); condition;) inspect(fn)\nconst token = fn?.(); }')

    def test_compact_iteration_declaration_keeps_captured_literal_refusal(self):
        for pattern, values in (('{fn}', '[{fn: () => VALUE}]'), ('[fn]', '[() => VALUE]')):
            with self.subTest(pattern=pattern):
                self.refuse('function caller(fn) { for (var' + pattern + ' of ' + values.replace('VALUE', repr(opaque())) + ') { const token = fn?.(); } }')

    def test_compact_iteration_public_key_keeps_outer_formal(self):
        self.accept('function caller(fn) { for (var{fn: other} of entries) { inspect(other); } const token = fn?.(); }')

    def test_multiline_balanced_loop_body_keeps_runtime_code(self):
        self.accept('function caller(fn) { for (const other of entries) inspect(\nother\n); const token = fn?.(); }')

    def test_loop_body_preserves_every_line_boundary(self):
        for point, comment in ((0x2028, False), (0x2029, False), (10, True), (13, True), (0x2028, True), (0x2029, True)):
            separator = ('/*' + chr(point) + '*/') if comment else chr(point)
            with self.subTest(code_point=point, comment=comment):
                self.refuse('function caller(){const fn=()=>'+repr(opaque())+';for(let fn=()=>operation();condition;)inspect(fn)'+separator+'const token=fn?.();}')

    def test_masked_loop_body_prefix_cannot_own_the_next_statement(self):
        for point in (10, 13, 0x2028, 0x2029):
            with self.subTest(code_point=point):
                self.refuse('function caller(){const fn=()=>'+repr(opaque())+';for(let fn=()=>operation();condition;)"body"'+chr(point)+'const token=fn?.();}')

    def test_loop_scope_cannot_cross_an_enclosing_closer(self):
        self.refuse('const fn=()=>'+repr(opaque())+';function caller(){for(let fn=()=>operation();condition;)inspect(fn)}const token=fn?.();')

    def test_continued_loop_expression_keeps_its_literal_origin(self):
        self.refuse('function caller(fn){for(let fn=()=>'+repr(opaque())+';condition;)inspect(fn)\n.next({token:fn?.()});}')

    def test_unrelated_asi_loop_keeps_outer_runtime_formal(self):
        self.accept('function caller(fn){for(let item=()=>operation();condition;)inspect(item)\nconst token=fn?.();}')

    def test_guarded_string_normalizer_keeps_literal_and_prototype_refusal(self):
        caller = 'import { normalize } from "./normalizer.js"; function view(input){const token=normalize(input.token);return {token};}'
        head = 'export function normalize(value){if(typeof value!=="string"){return undefined;}'
        normal = 'const trimmed=value.trim();return trimmed?trimmed:undefined;}'
        literal = repr(opaque())
        for written_caller, callee in (
            (caller, head + 'value=' + literal + ';' + normal),
            (caller, head + 'const trimmed=value.trim();return ' + literal + ';}'),
            ('String.prototype.trim=()=>'+literal+';'+caller, head+normal),
            (caller, 'String.prototype.trim=()=>'+literal+';'+head+normal),
        ):
            with self.subTest(caller=written_caller, callee=callee):
                with GUARD.captured_source_context([('entry.ts',written_caller),('normalizer.ts',callee)]):
                    self.refuse(written_caller)

    def test_selected_callback_formal_keeps_invocation_refusal(self):
        source = 'function producer(){return '+repr(opaque())+';} function factory(obj){return obj.fn();} function view(input){const token=factory({fn:producer});return {token};}'
        self.refuse(source)




    def test_parameter_member_keeps_ambiguous_captured_writer_refusal(self):
        source = 'function mutate(unrelated){return unrelated.other;} '
        source += 'function caller(owner){function mutate(target){target.value=' + repr(opaque()) + ';} mutate(owner);consume({token:owner.value});}'
        self.refuse(source)

    def test_parameter_member_keeps_unknown_external_code_allowance(self):
        self.accept('function caller(owner){external(owner);consume({token:owner.value});}')

    def test_parameter_member_keeps_captured_callback_writes(self):
        writers = (
            'function mutate(fn){fn.value=VALUE;}',
            'function mutate(fn){const alias=fn;alias.value=VALUE;}',
            'function writer(fn){fn.value=VALUE;} const mutate=writer;',
            'const mutate=(fn)=>{fn.value=VALUE;};',
            'const mutate=function(fn){fn.value=VALUE;};',
            'const mutate=fn=>{fn.value=VALUE;};',
            'function inner(fn){fn.value=VALUE;} function mutate(fn){inner(fn);}',
        )
        for writer in writers:
            for actual in ('owner', 'alias'):
                source = writer.replace('VALUE', repr(opaque()))
                source += 'function caller(owner){const alias=owner;mutate(' + actual + ');consume({token:owner.value});}'
                with self.subTest(writer=writers.index(writer), actual=actual):
                    self.refuse(source)

    def test_parameter_member_excludes_unrelated_callback_writes(self):
        for source in (
            'function mutate(fn){fn.other=VALUE;} function caller(owner){mutate(owner);consume({token:owner.value});}',
            'function mutate(fn){fn.value=VALUE;} function caller(owner,other){mutate(other);consume({token:owner.value});}',
        ):
            with self.subTest(source=source.index('VALUE')):
                self.accept(source.replace('VALUE', repr(opaque())))

    def test_selected_declared_function_keeps_argument_mutation_refusal(self):
        declaration = "function owner(input){return {value:input};} "
        mutation = "function mutate(fn){fn.value=" + repr(opaque()) + ";} "
        for escaped in ("mutate(owner);", "const alias = owner; mutate(alias);"):
            with self.subTest(escaped=escaped):
                self.refuse(declaration + mutation + escaped + "consume({token:owner.value});")

if __name__ == '__main__':
    unittest.main()
