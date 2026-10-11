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

CODE_PROJECTION_CASES = [['two-file-config-metadata', True, {'config.ts': 'export function makeConfig(raw){return {baseUrl:"https://public.example/", tokenEnv:raw.key};} export function readToken(config,env){return env[config.tokenEnv];}', 'tools.ts': 'import {makeConfig,readToken} from "./config.js"; export function run(raw,env){const config=makeConfig(raw); return consume({token:readToken(config,env)});}'}], ['two-file-without-unrelated-metadata', True, {'config.ts': 'export function makeConfig(raw){return {tokenEnv:raw.key};} export function readToken(config,env){return env[config.tokenEnv];}', 'tools.ts': 'import {makeConfig,readToken} from "./config.js"; export function run(raw,env){const config=makeConfig(raw); return consume({token:readToken(config,env)});}'}], ['one-file-config-metadata', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/", tokenEnv:raw.key};} function readToken(config,env){return env[config.tokenEnv];} function run(raw,env){const config=makeConfig(raw); return consume({token:readToken(config,env)});}'}], ['one-file-runtime-member-default', True, {'tools.ts': 'const defaults={env:process.env,call:externalCall}; function readToken(env){return env.PUBLIC_VALUE;} function run(deps=defaults){return deps.call({token:readToken(deps.env)});}'}], ['one-file-runtime-member-no-receiver', True, {'tools.ts': 'const defaults={env:process.env,call:externalCall}; function readToken(env){return env.PUBLIC_VALUE;} function run(deps=defaults){return consume({token:readToken(deps.env)});}'}], ['one-file-selected-public-literal', False, {'tools.ts': 'function makeConfig(){return {value:"public-origin-control"};} function readValue(config){return config.value;} function run(){const config=makeConfig(); return consume({token:readValue(config)});}'}], ['literal-return', False, {'tools.ts': 'function read(c,e){return "public-origin-control";} function run(c,e){consume({token:read(c,e)});}'}], ['formal-replacement', False, {'tools.ts': 'function read(value){value="public-origin-control";return value;} function run(value){consume({token:read(value)});}'}], ['callee-rebinding', False, {'tools.ts': 'function read(c,e){return e.PUBLIC_VALUE;} read=()=>"public-origin-control"; function run(c,e){consume({token:read(c,e)});}'}], ['selected-write', False, {'tools.ts': 'function read(c){return c.value;} function write(c,value){c.value=value;} function run(value){const c={value,metadata:"https://public.example/"};write(c,"OPAQUE_CONTROL");consume({token:read(c)});}'}], ['default-selected-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(d,value){d.env=value;} function run(deps=defaults){write(deps,"public-origin-control");consume({token:read(deps.env)});}'}], ['nested-selected-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults){write(deps.env,"public-origin-control");consume({token:read(deps.env)});}'}], ['unknown-selected-carrier-escape', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function run(deps=defaults){externalMutate(deps);consume({token:read(deps.env)});}'}], ['unknown-callee-literal-carrier', False, {'tools.ts': 'function run(env){const c={value:"public-origin-control"};consume({token:externalRead(c,env)});}'}], ['ambiguous-callee', False, {'tools.ts': 'function read(c,e){return e.PUBLIC_VALUE;} function read(c,e){return "OPAQUE_CONTROL";} function run(e){const c={metadata:"https://public.example/"};consume({token:read(c,e)});}'}], ['callee-alias-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,value){env.PUBLIC_VALUE=value;} const alias=write; function run(deps=defaults){alias(deps.env,"public-origin-control");consume({token:read(deps.env)});}'}], ['arrow-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} const write=(env,value)=>{env.PUBLIC_VALUE=value;}; function run(deps=defaults){write(deps.env,"public-origin-control");consume({token:read(deps.env)});}'}], ['selected-opaque-direct-return', False, {'tools.ts': 'function make(){return {value:"OPAQUE_CONTROL"};} function read(c){return c.value;} function run(){const c=make();consume({token:read(c)});}'}], ['selected-opaque-default-replacement', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function run(deps=defaults){deps={env:"OPAQUE_CONTROL"};consume({token:read(deps.env)});}'}], ['imported-selected-opaque-writer', False, {'config.ts': 'export function read(e){return e.PUBLIC_VALUE;} export function write(e,value){e.PUBLIC_VALUE=value;}', 'tools.ts': 'import {read,write} from "./config.js"; const defaults={env:process.env}; function run(deps=defaults){write(deps.env,"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['wrapped-selected-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(box,value){box.env.PUBLIC_VALUE=value;} function run(deps=defaults){write({env:deps.env},"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['captured-returned-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function identity(env){return env;} function read(e){return e.PUBLIC_VALUE;} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults){write(identity(deps.env),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['body-alias-selected-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function run(deps=defaults){const env=deps.env;env.PUBLIC_VALUE="OPAQUE_CONTROL";consume({token:read(deps.env)});}'}], ['callback-body-alias-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,value){const alias=env;alias.PUBLIC_VALUE=value;} function run(deps=defaults){write(deps.env,"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['computed-captured-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,key,value){env[key]=value;} function run(deps=defaults){write(deps.env,runtimeKey,"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['recursive-captured-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,value){if(externalFlag){write(env,"OPAQUE_CONTROL");}else{env.PUBLIC_VALUE=value;}} function run(deps=defaults,value){write(deps.env,value);consume({token:read(deps.env)});}'}], ['captured-selected-default', False, {'tools.ts': 'function read(env={PUBLIC_VALUE:"OPAQUE_CONTROL"}){return env.PUBLIC_VALUE;} function run(env){consume({token:read(env)});}'}], ['computed-selected-carrier-escape', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(box,key,value){externalMutate(box[key],value);} function run(deps=defaults){write(deps,runtimeKey,"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['conditional-selected-carrier-escape', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function write(env,value){externalMutate(externalFlag ? env : anotherEnv,value);} function run(deps=defaults){write(deps.env,"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['primitive-undefined-branch-runtime', True, {'tools.ts': 'const defaults={env:process.env}; function pick(candidates){return candidates.find(value=>value!==undefined);} function read(env){const value=env.PUBLIC_VALUE;return value?value:undefined;} function run(deps=defaults){consume({token:read(deps.env)});}'}], ['primitive-shadowed-undefined-captured-default', False, {'tools.ts': 'const defaults={env:process.env}; function pick(candidates){return candidates.find(value=>value!==undefined);} function read(env,undefined="OPAQUE_CONTROL"){const value=env.PUBLIC_VALUE;return value?value:undefined;} function run(deps=defaults){consume({token:read(deps.env)});}'}], ['captured-return-object-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function carrier(env){return {env};} function write(box,value){box.env.PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps.env),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['captured-return-array-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function carrier(env){return [env];} function write(box,value){box[0].PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps.env),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['captured-prototype-selected-write', False, {'tools.ts': 'const publicControlValue="OPAQUE_CONTROL"; Object.prototype.PUBLIC_VALUE=publicControlValue; const defaults={env:process.env,call:externalCall}; function readToken(env){return env.PUBLIC_VALUE;} function run(deps=defaults){return consume({token:readToken(deps.env)});}'}], ['typed-trailing-comma-runtime-selected', True, {'tools.ts': 'const defaults={env:process.env}; function read(\n config: PublicConfig,\n env: Record<string,string|undefined>=process.env,\n){return env.PUBLIC_VALUE;} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['typed-trailing-comma-literal-default', False, {'tools.ts': 'const defaults={env:process.env}; function read(\n config: PublicConfig,\n env: Record<string,string|undefined>= {PUBLIC_VALUE:"OPAQUE_CONTROL"},\n){return env.PUBLIC_VALUE;} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['typed-interior-empty-literal-default', False, {'tools.ts': 'const defaults={env:process.env}; function read(\n config: PublicConfig,,\n env: Record<string,string|undefined>= {PUBLIC_VALUE:"OPAQUE_CONTROL"},\n){return env.PUBLIC_VALUE;} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['runtime-computed-trim', True, {'tools.ts': 'const defaults={env:process.env}; function read(config,env=process.env){const value=env[config.tokenEnv]?.trim(); return value ? value : undefined;} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['computed-trim-literal-default', False, {'tools.ts': 'const defaults={env:{PUBLIC_VALUE:"OPAQUE_CONTROL"}}; function read(config,env){return env[config.tokenEnv]?.trim();} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['computed-trim-captured-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(config,env){env.PUBLIC_VALUE="OPAQUE_CONTROL";return env[config.tokenEnv]?.trim();} function run(config,deps=defaults){consume({token:read(config,deps.env)});}'}], ['computed-trim-returned-carrier', False, {'tools.ts': 'function makeEnv(){return {PUBLIC_VALUE:"OPAQUE_CONTROL"};} function read(config,env){return env[config.tokenEnv]?.trim();} function run(config){consume({token:read(config,makeEnv())});}'}], ['captured-member-return-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function carrier(box){return box.env;} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['captured-computed-return-carrier-write', False, {'tools.ts': 'const defaults={env:process.env}; function read(e){return e.PUBLIC_VALUE;} function carrier(box,key){return box[key];} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults,runtimeKey){write(carrier(deps,runtimeKey),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['grouped-return-runtime-code', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);return ({env:process.env,token:read(config,process.env)});}'}], ['omitted-literal-default', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env={PUBLIC_VALUE:"OPAQUE_CONTROL"}){return env.PUBLIC_VALUE;} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['shadowed-undefined-actual', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env.PUBLIC_VALUE;} function run(raw){const config=makeConfig(raw);const undefined={PUBLIC_VALUE:"OPAQUE_CONTROL"};consume({token:read(config,undefined)});}'}], ['omitted-runtime-default', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['omitted-default-with-unrelated-find', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function other(items){return items.find((item)=>item!==undefined);} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['native-default-explicit-undefined', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config,undefined)});}'}], ['renamed-helper-default', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function deriveScalar(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:deriveScalar(config)});}'}], ['captured-env-alias-default', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} const nativeEnv=process.env; function read(config,env=nativeEnv){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['local-env-alias-leaf', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){const selected=env;return selected[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['explicit-native-actual', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config,process.env)});}'}], ['literal-actual', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config,{PUBLIC_VALUE:"OPAQUE_CONTROL"})});}'}], ['unknown-actual', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw,foreignEnv){const config=makeConfig(raw);consume({token:read(config,foreignEnv)});}'}], ['data-actual-returned-by-helper', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function data(){return {PUBLIC_VALUE:"OPAQUE_CONTROL"};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config,data())});}'}], ['array-actual', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config,["OPAQUE_CONTROL"])});}'}], ['returned-env-identity', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env;} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['returned-leaf-object', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return {value:env[config.tokenEnv]?.trim()};} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['returned-leaf-array', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return [env[config.tokenEnv]?.trim()];} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['custom-method', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.customMethod();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['method-identity', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim;} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['method-with-argument', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim(config);} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['shadowed-process-default', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env,process){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['data-process-shadow', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} const process={env:{PUBLIC_VALUE:"OPAQUE_CONTROL"}}; function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['whole-env-replacement', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} process.env={PUBLIC_VALUE:"OPAQUE_CONTROL"}; function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['default-binding-overridden', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){env={PUBLIC_VALUE:"OPAQUE_CONTROL"};return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['selected-env-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){env[config.tokenEnv]="OPAQUE_CONTROL";return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['selected-config-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){config.tokenEnv="OPAQUE_CONTROL";return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['env-alias-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){const selected=env;selected[config.tokenEnv]="OPAQUE_CONTROL";return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['native-env-object-operation', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){Object.assign(env,{PUBLIC_VALUE:"OPAQUE_CONTROL"});return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['env-escape-before-scalar', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){unknown(env);return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['string-prototype-method-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} String.prototype.trim=function(){return "OPAQUE_CONTROL";}; function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['captured-sibling-prototype-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'String.prototype.trim=function(){return "OPAQUE_CONTROL";};'}], ['captured-sibling-env-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'process.env.PUBLIC_VALUE="OPAQUE_CONTROL";'}], ['captured-sibling-env-alias-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'const environment=process.env;environment.PUBLIC_VALUE="OPAQUE_CONTROL";'}], ['prototype-key-computed-lookup', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.constructor]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['captured-unknown-env-escape', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'unknown(process.env);'}], ['captured-alias-unknown-env-escape', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'const environment=process.env;unknown(environment);'}], ['captured-callee-env-write', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'function mutate(target){target.PUBLIC_VALUE="OPAQUE_CONTROL";} mutate(process.env);'}], ['captured-callee-no-write', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'function inspect(target){return target.PUBLIC_VALUE;} inspect(process.env);'}], ['canonical-env-computed-leaf', True, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv];} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['string-method-define-property', False, {'tools.ts': 'Object.defineProperty(String.prototype,"trim",{value:function(){return {value:"OPAQUE_CONTROL"};}});function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['unknown-env-default', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=foreignEnv){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}'}], ['captured-process-replacement', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'process={env:{PUBLIC_VALUE:"OPAQUE_CONTROL"}};'}], ['captured-global-process-replacement', False, {'tools.ts': 'function makeConfig(raw){return {baseUrl:"https://public.example/",tokenEnv:raw.key};} function read(config,env=process.env){return env[config.tokenEnv]?.trim();} function run(raw){const config=makeConfig(raw);consume({token:read(config)});}', 'sibling.ts': 'globalThis.process={env:{PUBLIC_VALUE:"OPAQUE_CONTROL"}};'}], ['local-alias-residual-member-write', False, {'tools.ts': 'const defaults={env:process.env};function read(e){return e.PUBLIC_VALUE;} function carrier(box){const value=box.env;return value;} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['local-alias-returned-object-write', False, {'tools.ts': 'const defaults={env:process.env};function read(e){return e.PUBLIC_VALUE;} function carrier(box){const value=box.env;return {env:value};} function write(env,value){env.env.PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['local-alias-returned-array-write', False, {'tools.ts': 'const defaults={env:process.env};function read(e){return e.PUBLIC_VALUE;} function carrier(box){const value=box.env;return [value];} function write(env,value){env[0].PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['computed-custom-method-owner-write', False, {'tools.ts': 'const defaults={env:process.env};function read(e){return e.PUBLIC_VALUE;} function carrier(box){return box[runtimeKey].identity();} function write(env,value){env.PUBLIC_VALUE=value;} function run(deps=defaults){write(carrier(deps),"OPAQUE_CONTROL");consume({token:read(deps.env)});}'}], ['keyword-return-member-write', False, {'tools.ts': 'export {};\nconst defaults={env:process.env};\nfunction read(e){return e.PUBLIC_VALUE;}\nconst writer={return(env,value){env.PUBLIC_VALUE=value;}};\nfunction run(deps=defaults){writer.return(deps.env,"A7f9K2m4Q8v6N3x5R1p0T9z8");consume({token:read(deps.env)});}\n'}], ['keyword-return-optional-member-write', False, {'tools.ts': 'export {};\nconst defaults={env:process.env};\nfunction read(e){return e.PUBLIC_VALUE;}\nconst writer={return(env,value){env.PUBLIC_VALUE=value;}};\nfunction run(deps=defaults){writer?.return(deps.env,"A7f9K2m4Q8v6N3x5R1p0T9z8");consume({token:read(deps.env)});}\n'}], ['keyword-throw-member-write', False, {'tools.ts': 'export {};\nconst defaults={env:process.env};\nfunction read(e){return e.PUBLIC_VALUE;}\nconst writer={throw(env,value){env.PUBLIC_VALUE=value;}};\nfunction run(deps=defaults){writer.throw(deps.env,"A7f9K2m4Q8v6N3x5R1p0T9z8");consume({token:read(deps.env)});}\n'}], ['keyword-throw-optional-member-write', False, {'tools.ts': 'export {};\nconst defaults={env:process.env};\nfunction read(e){return e.PUBLIC_VALUE;}\nconst writer={throw(env,value){env.PUBLIC_VALUE=value;}};\nfunction run(deps=defaults){writer?.throw(deps.env,"A7f9K2m4Q8v6N3x5R1p0T9z8");consume({token:read(deps.env)});}\n'}], ['function-shadowed-undefined-member-write', False, {'tools.ts': 'export {};\nconst defaults={env:process.env};\nfunction undefined(){}\nundefined.PUBLIC_VALUE="A7f9K2m4Q8v6N3x5R1p0T9z8";\nfunction read(env=process.env){return env.PUBLIC_VALUE;}\nfunction run(){consume({token:read(undefined)});}\n'}], ['shadowed-name-invoked-source-call', True, {'tools.ts': 'function undefined(){return process.env.PUBLIC_VALUE;} function read(value){return value;} consume({token:read(undefined())});'}], ['shadowed-name-selected-runtime-member', True, {'tools.ts': 'function undefined(){} undefined.PUBLIC_VALUE=runtimeValue; function read(value){return value;} consume({token:read(undefined.PUBLIC_VALUE)});'}]]

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


    def test_scoped_call_projection_keeps_selected_origins_and_effects(self):
        for name, accepted, templates in CODE_PROJECTION_CASES:
            with self.subTest(case=name):
                sources = {path: source.replace("OPAQUE_CONTROL", opaque()) for path, source in templates.items()}
                with GUARD.captured_source_context(sources.items()):
                    check = self.accept if accepted else self.refuse
                    check(sources["tools.ts"], "tools.ts")


if __name__ == '__main__':
    unittest.main()
