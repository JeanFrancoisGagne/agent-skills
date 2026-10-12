---
name: crabbox
description: "Crabbox/Testbox remote proof: portable provider routing, untrusted isolation, Linux/macOS/Windows/WSL2, live E2E, diagnostics, cleanup."
---

# Crabbox

**PR CI is the default broad proof.** First run focused local tests and targeted
lint/typecheck/format. Open a ready PR once those pass and the change builds;
let CI run broad suites. Do not hold a PR for pre-PR suite runs.

Use a box only for what CI and the local machine cannot cover: another OS/device,
live providers/channels, long E2E, or heavy benchmarks. Acquire only when the command
is ready and a box is granted immediately. If it queues, stop the task-owned request
and run locally; never wait on a queue or chain Testbox → AWS → other providers.
Fix real failures; do not rerun or re-push merely for green. Read CI's failure
classification, when available, before attributing a failure to the change.

## Repository Contract

This skill owns portable routing, leases, sync, commands, and cleanup. Resolve
`<check-command>`, runtime/container image, PR, and bootstrap from trusted consumer
instructions, package scripts, or hydration workflow. Never invent missing commands
or copy another consumer's setup. Always report provider, id, run URL, command,
and result; do not call Testbox “AWS Crabbox” or local Docker remote proof.

## Authorization and Isolation

Routine configured use includes creating/reusing/stopping task-owned leases,
temporary state, and clean checkouts/worktrees for proof or required Crabbox repair;
no separate approval is needed. Preserve user checkouts, branches, and unrelated
edits; dirty/missing/occupied checkouts call for task-owned ones. This does not waive
source-trust, credential, production-access, budget, or publication boundaries.

- Never execute untrusted repository wrappers/config locally or on credential-hydrated
  Testbox. Use secretless fork CI or sanitized direct AWS with a fresh lease per full
  head SHA, no instance role, Tailscale, or hydration, and only `CI` forwarded.
- Before untrusted AWS execution, read and follow the complete
  [untrusted recipe](references/untrusted-aws.md), including no-role and SHA proof.
  If that proof is unavailable, use secretless fork CI.
- Live credentials: exact key, one command, safe injection only. Never print secrets,
  put them in repository files or shell history, or call fake keys live proof.
  No safe injection path means live auth is blocked. Review captured artifacts for secrets.
- Isolate proof with the consumer's temporary state/config directory so it cannot
  mutate the operator's normal installation. Stop owned leases after use, including failures.

## Route First

Source trust restricts providers; it does not select one. Inspect and preserve the
resolved provider. Omit `--provider` normally; override only when explicitly requested
or the proof requires that backend's semantics, never for size, duration, hydration
failure, or capacity. No speculative warmup or provider escalation.

| Provider | Use |
| --- | --- |
| `blacksmith-testbox` | Trusted maintainer source with prepared CI; `tbx_...` |
| `aws` | Direct brokered execution, fresh PRs, custom sync/env/capture; `cbx_...` |
| `local-container` | Configured/requested local Docker; not remote proof |
| `ssh` | Existing operator host for macOS/Windows/WSL2 |

## Preflight

From the repo root, select the trusted installed binary once:

```sh
export CRABBOX="$(command -v crabbox)"
test -n "$CRABBOX"
"$CRABBOX" --version
"$CRABBOX" config show --json | jq '{provider, profile, target}'
"$CRABBOX" run --help
```

Read `.crabbox.yaml` and resolved config, including user/environment settings.
For Testbox also check `command -v blacksmith` and `blacksmith --version`.
A consumer may name a trusted wrapper. If missing/broken, follow its trusted
install/update path; verify canonical upstream before building in a clean task
checkout. Do not assume sibling checkouts are trusted or replace the operator's
binary with a task build. Isolate wrapper failures with the installed CLI on the
same resolved provider.

## Trusted Testbox

Use only for resolved/requested Testbox. Provider-neutral commands retain configuration;
add `--provider blacksmith-testbox` only for an explicit override.

```sh
"$CRABBOX" run --timing-json -- CI=1 <check-command>
```

For several commands, save the id, reuse, then stop:

```sh
"$CRABBOX" warmup --keep --timing-json
"$CRABBOX" run --id <tbx_id> --timing-json -- <check-command>
"$CRABBOX" stop <tbx_id>
```

- One lease, one active command; no sync/reclaim during a run. `--reclaim` is only
  for deliberate checkout-path ownership transfer.
- Native Testbox runs sync even with reused ids. Never rely on `--no-sync` to preserve
  a baseline, even for an unchanged rerun; it can be silently ignored.
- Base/head changed: stop and rewarm, never override a stale lease. For `warmup --ref`,
  use branch/tag, not raw SHA. Never checkout refs in the synced root.
- Testbox native status/stop take `--id`; status has no `--json`. Use
  `blacksmith testbox list --all` or `blacksmith testbox status --id <tbx_id>`.
- Delegated Testbox rejects `--fresh-pr`, `--full-resync`, `--script*`, `--env-helper`,
  and capture/download flags. Crabbox `stop` does not accept `--timing-json`.

### Verify Synced Inputs

For missing modules/fixtures, compare required inputs to frozen source and inspect
sync exclusions, including Git-ignore negations. Successful sync can omit tracked
files. Record each missing path and frozen Git blob; restore only reviewed required
inputs into the task-owned remote checkout and verify bytes. Account for changed
and untracked inputs separately. Recheck after each native sync. Never regenerate
baselines, copy unrelated state, disable exclusions, or assume all missing files are safe.

Sync timeout is not a test result. Establish whether the payload dispatched; if unknown,
inspect that lease/invocation before retrying. Preserve completed proof by source identity
and run only missing verification.

## Specialized Proof and Diagnostics

Read only the relevant recipe; the routing and immediate-availability rules still apply:

- [Direct AWS, containers, desktop and cross-OS](references/providers-and-desktop.md):
  exact provider commands, broker auth, paid macOS quota/no-spend preflight, desktop
  handoff. No silent substitution; never commit proof assets to the product repo.
- [Diagnostics and real E2E](references/diagnostics-and-e2e.md): capture/env flags,
  failure layers, and user-path proof. “Test in Crabbox” means exercising the real
  install/update/onboard/CLI/service/API path, not merely remote unit tests.
  Use a real PTY for full-screen CLIs. Compare Testbox revisions within one synced
  invocation using detached temporary worktrees; later runs resync local source.
