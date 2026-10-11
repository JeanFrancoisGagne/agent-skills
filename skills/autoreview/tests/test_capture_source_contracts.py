"""Immutable captured sources keep genuine credential refusal."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('capture_guard', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def opaque():
    return 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'


def isolated_source(token='recorded-session-token', key='recorded-upstream-key'):
    return '''import os
import unittest
from unittest.mock import patch
import httpx
class Checks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"APP_TOKEN": TOKEN_VALUE}).start()
        patch("socket.create_connection", side_effect=AssertionError("network forbidden")).start()
        patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")).start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
            base_url="https://fixture.invalid", headers={"authorization": BEARER}, trust_env=False)
    async def test_request(self):
        def recorded(request):
            return response
        patch.object(provider, "_API_KEY", KEY).start()
        patch.object(provider, "urlopen", recorded).start()
'''.replace('TOKEN_VALUE', repr(token)).replace('BEARER', repr('Bearer ' + token)).replace('KEY).', repr(key) + ').')


class CaptureSourceContractTests(unittest.TestCase):
    def test_isolated_public_placeholders_admit(self):
        GUARD.require_safe_source('file source', 'checks.py', isolated_source())

    def test_opaque_token_still_refuses_in_isolated_asgi(self):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', 'checks.py', isolated_source(token=opaque()))

    def test_provider_key_shape_still_refuses_in_mock(self):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', 'checks.py', isolated_source(key='sk-' + opaque()))

    def test_missing_isolation_keeps_placeholder_refusal(self):
        source = isolated_source().replace('patch("socket.create_connection", side_effect=AssertionError("network forbidden")).start()', 'pass')
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('file source', 'checks.py', source)

    def test_bearer_data_without_source_contract_refuses(self):
        with self.assertRaises(SystemExit):
            GUARD.require_no_secret_values('data', 'Bearer recorded-session-token')




class CapturedCalleeTests(unittest.TestCase):
    def capture(self, caller, callee=None, config=None):
        import importlib.machinery
        import sys
        import tempfile
        from types import SimpleNamespace
        path = SCRIPT.with_name('autoreview')
        spec = importlib.util.spec_from_loader('capture_helper', importlib.machinery.SourceFileLoader('capture_helper', str(path)))
        helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = helper
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / 'caller.ts').write_text(caller)
            paths = ['caller.ts']
            if callee is not None:
                (repo / 'select.ts').write_text(callee)
                paths.append('select.ts')
            if config is not None:
                import json
                (repo / 'tsconfig.json').write_text(json.dumps(config))
                paths.append('tsconfig.json')
            args = SimpleNamespace(prompt=[], prompt_file=[], dataset=paths)
            return helper, helper.capture_evidence_inputs(args, repo)

    def test_captured_read_only_return_keeps_reference(self):
        caller = "import { pick } from './select.js';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        _, evidence = self.capture(caller, 'export function pick(input) { return input.value; }\n')
        self.assertEqual([row.raw_path for row in evidence.files], ['caller.ts', 'select.ts'])

    def test_mutating_captured_callee_refuses(self):
        caller = "import { pick } from './select.js';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller, 'const hidden = ' + repr(opaque()) + ';\nexport function pick(input) { input.value = hidden; return input.value; }\n')

    def test_missing_captured_callee_refuses(self):
        caller = "import { pick } from './select.js';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller)

    def test_returned_credential_origin_refuses(self):
        caller = "import { pick } from './select.js';\nconst credential = pick(supplied);\nconsume({token: credential});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller, 'export function pick(input) { return ' + repr(opaque()) + '; }\n')

    def test_checked_primitive_result_does_not_carry_mutable_root(self):
        caller = "import { checked } from './select.js';\nconst state = {value: supplied};\nconst ready = checked(state.value);\npatch(ready);\nconsume({token: state.value});\n"
        self.capture(caller, 'export function checked(value) { return typeof value === "string" ? value : undefined; }\n')

    def test_annotated_unknown_result_stays_unproved(self):
        caller = "import { checked } from './select.js';\nconst state = {value: supplied};\nconst ready = checked(state.value);\npatch(ready);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller, 'export function checked(value): string { return unknown(value); }\n')


    def test_nonexported_callee_stays_unproved(self):
        caller = "import { pick } from './select.js';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller, 'function pick(input) { return input.value; }\n')

    def test_changed_callee_refuses_revalidation(self):
        import importlib.machinery
        import sys
        import tempfile
        from types import SimpleNamespace
        path = SCRIPT.with_name('autoreview')
        spec = importlib.util.spec_from_loader('verify_capture_helper', importlib.machinery.SourceFileLoader('verify_capture_helper', str(path)))
        helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = helper
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            caller = "import { pick } from './select.js';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
            (repo / 'caller.ts').write_text(caller)
            (repo / 'select.ts').write_text('export function pick(input) { return input.value; }\n')
            args = SimpleNamespace(prompt=[], prompt_file=[], dataset=['caller.ts', 'select.ts'])
            evidence = helper.capture_evidence_inputs(args, repo)
            originals = [(row.raw_path, row.content) for row in evidence.files]
            (repo / 'select.ts').write_text('export function pick(input) { return ' + repr(opaque()) + '; }\n')
            with self.assertRaises(SystemExit):
                helper.verify_evidence(repo, evidence.files)
            self.assertEqual(originals, [(row.raw_path, row.content) for row in evidence.files])


    def test_captured_compiler_alias_keeps_read_only_reference(self):
        caller = "import { pick } from '@owned/select';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        self.capture(caller, 'export function pick(input) { return input.value; }\n',
                     {'compilerOptions': {'paths': {'@owned/select': ['./select.ts']}}})

    def test_malformed_captured_compiler_paths_remain_unproved(self):
        caller = "import { pick } from '@owned/select';\nconst state = {value: supplied};\npick(state);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            self.capture(caller, 'export function pick(input) { return input.value; }\n',
                         {'compilerOptions': {'paths': []}})


class MethodScopeOriginTests(unittest.TestCase):
    def test_method_parameter_is_not_an_enclosing_object_capture(self):
        source = '''const defaults = resolveDefaults();
export const testing = {
    configure(deps) { runtime.loadDeviceAuthToken = deps?.loadDeviceAuthToken ?? defaults.loadDeviceAuthToken; },
    reset() { runtime.loadDeviceAuthToken = defaults.loadDeviceAuthToken; },
};
'''
        GUARD.require_safe_source('whole method owner', 'method.ts', source)

    def test_method_assignment_retains_literal_refusal(self):
        source = 'const testing = { configure(deps) { runtime.loadDeviceAuthToken = ' + repr(opaque()) + '; } };'
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('whole method owner', 'method.ts', source)

    def test_free_mutable_root_in_method_remains_a_carrier(self):
        source = "const state = {value: supplied};\nconst carried = {rewrite(other) { state.value = hidden; }};\npatch(carried);\nconsume({token: state.value});\n"
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('whole method owner', 'method.ts', source)

class CodeRoleControls(unittest.TestCase):
 def test_owned_formal_and_selected_symbol_are_code(self):
  source='function view(requestAuth) { const selectedApiKey = requestAuth.apiKey; return {apiKey: requestAuth.apiKey, token: selectedApiKey}; }\n'
  GUARD.require_safe_source('file source','caller.ts',source)
 def test_declared_normalizer_result_is_code(self):
  caller='import { normalize } from "./normalizer.js";\nfunction view(input) { const token = normalize(input.token); return {token}; }\n'
  callee='export function normalize(value) { if (typeof value !== "string") { return undefined; } const trimmed=value.trim(); return trimmed ? trimmed : undefined; }\n'
  with GUARD.captured_source_context([('caller.ts',caller),('normalizer.ts',callee)]):GUARD.require_safe_source('file source','caller.ts',caller)
 def test_literal_assigned_to_formal_field_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  source='function view(input) { input.value = '+repr(value)+'; return {token: input.value}; }\n'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('file source','caller.ts',source)
 def test_unknown_data_carrier_remains_refused(self):
  source='const state={value:supplied}; const carried={node:state}; unknown(carried); consume({token:state.value});\n'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('file source','caller.ts',source)
 def test_declared_result_with_literal_return_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  caller='import { normalize } from "./normalizer.js";\nfunction view(input) { const token=normalize(input.token); return {token}; }\n'
  callee='export function normalize(value) { return '+repr(value)+'; }\n'
  with GUARD.captured_source_context([('caller.ts',caller),('normalizer.ts',callee)]):
   with self.assertRaises(SystemExit):GUARD.require_safe_source('file source','caller.ts',caller)

class ActualSourceShapes(unittest.TestCase):
 def test_conditional_parameter_normalization(self):
  source='export function resolve(opts?: Auth): Auth { const token=typeof opts?.token === "string" && opts.token.trim().length > 0 ? opts.token.trim() : undefined; return {token}; }'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_asserted_selected_fallback(self):
  source='import { state } from "./state.js"; export function start(token?: string) { if(typeof token === "string") {state.auth={mode:"token",token};} const fallbackToken=token ?? (typeof (state.auth as {token?:unknown}|undefined)?.token === "string" ? (state.auth as {token?:string}).token : undefined); return {token:fallbackToken}; }'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_mutable_own_value_call_refuses(self):
  source='function read(input){const state={value:input}; unknown(state); return {token:state.value};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)
 def test_mutable_own_value_receiver_refuses(self):
  source='function read(input){const state={value:input}; state.rewrite=function(){this.value=input;}; state.rewrite(); return {token:state.value};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)

class LiteralSuffix(unittest.TestCase):
 def test_conditional_literal_suffix_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  source='function view(input){const token=input ? input.token+'+repr(value)+' : undefined;return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)

class FixtureOccurrenceControls(unittest.TestCase):
    def test_same_bearer_in_unrelated_data_refuses(self):
        source = isolated_source() + '\nrecord = {"authorization": "Bearer recorded-session-token"}\n'
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('source', 'fixture.py', source)

    def test_same_bearer_in_decoded_data_refuses(self):
        source = isolated_source() + '\npayload = ' + repr('{"authorization": "Bearer recorded-session-token"}') + '\n'
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source('source', 'fixture.py', source)




class CodeRoleOwnerBoundary(unittest.TestCase):
 def test_owned_callable_field_reference(self):
  source='function load(input){return input.value;} const deps:{load:typeof load}={load}; function read(input){return deps.load(input);} consume({token:deps.load});'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_selected_existing_fixture_origin(self):
  source='import {state} from "./state.js"; state.auth={token:"test-token"}; function read(input){return {token:state.auth.token};}'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_object_rest_has_lexical_identity_only(self):
  source='function first(token){return {token};} function second(opts){const {header,...rest}=opts;const token=opts.token;return {token};}'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_selected_imported_credential_write_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  source='import {state} from "./state.js"; state.auth={token:'+repr(value)+'}; consume({token:state.auth.token});'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)
 def test_callable_receiver_with_this_write_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  source='const hidden='+repr(value)+';function load(){this.load=hidden;}const deps={load};deps.load();consume({token:deps.load});'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)
 def test_callable_container_unproved_argument_refuses(self):
  source='function load(input){return input.value;} const deps={load}; unknown(deps); consume({token:deps.load});'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)


class ExistingGlobalReferenceControls(unittest.TestCase):
 def test_existing_environment_selector_is_code(self):
  source='function view(input){const token=input.enabled ? input.token : process.env.ACCESS_TOKEN;return {token};}'
  GUARD.require_safe_source('source','caller.ts',source)
 def test_shadowed_literal_environment_refuses(self):
  value='A7f9K2m4Q8v6'+'N3x5R1p0T9z8'
  source='const env={token:'+repr(value)+'};consume({token:env.token});'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('source','caller.ts',source)
 def test_same_reference_bytes_in_data_refuse(self):
  with self.assertRaises(SystemExit):GUARD.require_safe_source('data','input.json','{"token":"env.token"}')


class SourceOccurrenceBoundary(unittest.TestCase):
 def test_conditional_resolver_with_metadata_and_arrow_source(self):
  source='''const readConfig=async (): Promise<Config> => (await import("./config.js")).read();
async function contextFor(opts){const urlOverrideSource=opts.cliUrl ? "cli" : opts.envUrl ? "env" : undefined;const config=await readConfig();return {config,urlOverrideSource,explicitAuth:opts.auth};}
async function resolve(context){return {token:context.explicitAuth.token,password:context.explicitAuth.password};}
async function send(opts){const context=await contextFor(opts);const resolvedCredentials=opts.useStored ? {} : await resolve(context);const token=opts.useStored ? undefined : resolvedCredentials.token;const password=opts.useStored ? undefined : resolvedCredentials.password;return {token,password,approvalRuntimeToken:opts.token};}
'''
  GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_conditional_resolver_literal_return_refuses(self):
  source='async function resolve(input){return '+repr(opaque())+';} async function send(opts){const token=opts.useStored ? undefined : await resolve(opts);return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_conditional_resolver_constructed_return_refuses(self):
  value=opaque()
  source='async function resolve(input){return '+repr(value[:12])+'+'+repr(value[12:])+';} async function send(opts){const token=opts.useStored ? undefined : await resolve(opts);return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_same_expression_in_data_refuses(self):
  source='{"token":"useStored ? undefined : await resolve(context)"}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('data','input.json',source)

 def test_typed_module_and_selector_owner_occurrences(self):
  source='''type Details={urlSource:string};
const readConfig=async ():Promise<Config> => (await import("../config/io.js")).read();
function describe(options:{urlSource?:"cli"|"env"}){return {urlSource:options.urlSource};}
async function contextFor(opts){const cliUrlOverride=opts.url;const envUrlOverride=opts.envUrl;const urlOverrideSource=cliUrlOverride ? "cli" : envUrlOverride ? "env" : undefined;const config=await readConfig();describe({urlSource:urlOverrideSource});return {config,urlOverrideSource,explicitAuth:opts.auth};}
async function resolve(context){return {token:context.explicitAuth.token};}
async function send(opts){const context=await contextFor(opts);const resolvedCredentials=opts.useStored ? {} : await resolve(context);return {token:resolvedCredentials.token};}
'''
  GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_module_selector_keeps_credential_uri_refusal(self):
  source='const read=async ():Promise<Config> => (await import("https://user:'+opaque()+'@fixture.invalid/config.js")).read();async function send(input){const token=await read();return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)

 def test_declaration_return_keeps_owned_data_escape_refusal(self):
  source='function read(input){const state={value:input};unknown(state);return state.value;}function send(input){const token=read(input);return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)

 def test_typed_arrow_function_field_is_code(self):
  source='const read=async ():Promise<Config> => (await import("../config/io.js")).read();const deps:{read:typeof read}={read};function send(input){return {token:deps.read};}'
  GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_arrow_field_literal_return_refuses(self):
  source='const read=():string => '+repr(opaque())+';const deps={read};function send(input){return {token:deps.read()};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)

 def test_parameter_projection_with_unrelated_overload_is_code(self):
  source='function spare(input:string):string;function spare(input){return input;}function send<T>(params:{opts:Options}):T{const {opts}=params;return invoke({...(opts.approvalRuntimeToken ? {approvalRuntimeToken:opts.approvalRuntimeToken} : {}),...(opts.agentRuntimeIdentityToken ? {agentRuntimeIdentityToken:opts.agentRuntimeIdentityToken} : {})});}'
  GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_overload_projection_keeps_shadowed_data_refusal(self):
  source='function spare(input:string):string;function spare(input){return input;}function send(opts){function inner(){const opts={value:supplied};unknown(opts);return {token:opts.value};}return inner();}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)
 def test_returned_regex_literal_source_refuses(self):
  source='function read(){const value=/'+opaque()+'/;return value.source;}function send(){const token=read();return {token};}'
  with self.assertRaises(SystemExit):GUARD.require_safe_source('whole captured code','caller.ts',source)

if __name__ == '__main__':
    unittest.main()
