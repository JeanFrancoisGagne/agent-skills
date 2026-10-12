# Engine options

Read for model/effort overrides, provider projection, or optional engines.

Defaults and engine-selection policy live in [SKILL.md](../SKILL.md#engines).
Explicit `gpt-6.1-sol` selections retain the same access-only `gpt-6-sol` retry. Explicit `gpt-6-sol` selections retain their access-only `gpt-6-luna` retry;
other explicit models, including Luna and Astra, have no model fallback.
Explicit `gpt-5.6-sol` selections retain their access-only `gpt-5.6-terra` retry.
GPT-6.1 Sol rejects `none` and `minimal` effort before review preparation;
GPT-6 Sol and Luna reject `minimal`. An effort-only override keeps the default model.
Honor explicit user engine/model choices.
The helper does not automatically fall back between engines.

Use `--engine`, `--model`, and `--thinking` to override the defaults.
The Codex tier defaults to Ultrafast when the active model catalog lists it (Codex
otherwise silently sends the standard tier); a raw `--codex-config service_tier=...`
keeps its value. `--codex-speed fast` selects priority service, and
`--codex-speed default` selects the standard tier. Only Claude accepts
`--fallback-model`. Per-engine environment overrides use `AUTOREVIEW_<ENGINE>_*`.

If your account cannot access Sol or Luna, pin an available model. To require
GPT-6 Astra without a model fallback, select it explicitly:

```bash
"$AUTOREVIEW" --mode local --model gpt-6-astra --thinking high
```

GPT-6.1 Sol and GPT-6 Astra support `low`, `medium`, `high`, `xhigh`, and `max`;
neither supports `none` or `minimal`. GPT-6 Sol and Luna additionally support `none`,
but not `minimal`. AutoReview defaults to
`medium` and does not fall back from an explicit Luna or Astra selection.
Codex's `ultra` mode uses automatic
delegation and is outside this helper's supported effort levels. Use `max`
for its deepest supported review. For EU data residency, use
`--codex-speed default`; GPT-6 fast mode is unavailable there.
See the [GPT-6.1 Sol](https://developers.openai.com/api/docs/models/gpt-6.1-sol),
[GPT-6 Sol](https://developers.openai.com/api/docs/models/gpt-6-sol), and
[GPT-6 Luna](https://developers.openai.com/api/docs/models/gpt-6-luna) model docs
and [Codex reasoning modes](https://learn.chatgpt.com/docs/models#know-when-to-use-max-or-ultra).

By default, Codex preserves only authentication settings from user configuration;
provider, profile, context and catalogue settings remain ignored. To project a
named route, select it explicitly through the existing config override:

```bash
"$AUTOREVIEW" --mode local --codex-config 'model_provider="review_api"'
```

The selector must match `model_provider` in the operator's external
`CODEX_HOME/config.toml`. It accepts one bare or simply quoted identifier;
provider definitions and other capabilities cannot be supplied through overrides.
Projection requires Python 3.11 or `tomli`; default auth-only operation retains
its existing fallback parser.

The selected route must use `https://api.openai.com/v1` and command authentication
with an absolute external executable. Fixed arguments belong in that executable's
wrapper; omitted or empty `auth.args` are accepted. Omitted `wire_api` and
`requires_openai_auth` retain Codex's `responses` and `false` defaults. Optional
auth timing and context settings keep native defaults and semantics.

On POSIX, a private launcher restores the validated caller `HOME` only for the
selected authentication executable; the engine and reviewer tools retain their
isolated environment and filesystem access. Caller `HOME` must be an available
absolute directory with no repository-owned path or symlink provenance. Windows
keeps the native executable route. Command-auth runs suppress raw provider
diagnostics and report fixed failure categories, while retaining compact progress,
usage and assistant report streaming. An empty final report fails without exposing
captured stdout.

Catalogue and authentication working-directory paths resolve relative to the
operator config directory and must remain outside the reviewed repository.
A supplied catalogue is copied byte-for-byte into the private client runtime;
retries use the same route and catalogue snapshot. Dry runs check the same
ownership and route shape without executing authentication. Codex owns catalogue
validation, model access and context clamping. Other custom provider forms and
split context overrides are unsupported when projection is selected.

| Optional engine | Prerequisites                                                                                         |
| --------------- | ----------------------------------------------------------------------------------------------------- |
| Claude          | CLI 2.1.169+; safe mode with web-only tools                                                           |
| Amp             | `AMP_API_KEY` for a plugin-free account; local POSIX execution, no custom endpoint or cloud/orb agent |
| Pi              | CLI 0.79.0+; configured model; no tools or project resources                                          |

`--engine kimi` remains recognized but is refused for reviews and `--dry-run`
before any Kimi process, configuration read or authentication setup. The supported
Kimi Code prompt mode accepts review content only as a command-line argument;
the helper has no supported private prompt input channel for it. This intentionally
retires the previous Kimi execution path rather than exposing the bundle in process
arguments. Existing `--kimi-bin` arguments remain accepted for the same clear refusal;
the helper never silently selects another engine. A custom agent file is not an
equivalent replacement because it changes the input into a templated system prompt.
