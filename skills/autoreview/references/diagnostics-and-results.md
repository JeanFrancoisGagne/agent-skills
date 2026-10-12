# Diagnostic and result guidance

Exit codes, result interpretation, and finding decisions live in
[SKILL.md](../SKILL.md#diagnostics-and-results). Read this file for output-path
edge cases, machine status, usage accounting, or local stage observation.

## Local stage diagnostic

Use `--engine-stage-dir /outside/repo/fresh-private-directory` with
`--stream-engine-output` to observe the first streamed Codex process. Create and
exclusively hold a fresh mode-`0700` directory on responsive local POSIX storage.
The helper neither creates it nor overwrites `engine-stage.json`. There is no
observation for other engines, buffered output, or dry runs; no environment
variable activates it.

The sidecar holds only closed booleans/enums, at most 4096 bytes: local launch,
read, parser, display, and first-process terminal observations. Retries/passes do
not update it, and its terminal state can differ from the review outcome.
`spoofable` is always true; `provider_receipt` and `acceptance` are always false.
Missing/false means unknown, not provider activity, native initialization, or
acceptance. The redaction wrapper leaves flushed-display observations unknown.

Ordinary observation/persistence failures preserve the primary result. Persistence
rejects repository paths, symlinks, unsafe ownership/permissions, and existing names.
Failed cleanup may leave a private `.engine-stage.partial` or an unresolved
closure; retain custody when clearing it. Ambiguous closes are not retried.
Cancellation propagates; cleanup cancellation can replace a pending exception
after remaining attempts. Assumes ordinary descriptor acquisition/assignment,
trusted caller custody, and responsive storage, not hostile same-user interference,
concurrent descriptor reuse, arbitrary interruption, network/stalled filesystems,
or crash durability. It changes no report, usage, deadline, exit, or isolation rule.

## Results

All output paths must be outside the repo as both final entries (after resolving
parent symlinks) and resolved referents. Without `--status-output`, human and JSON
outputs must name distinct final entries; distinct symlinks/hardlinks may share
an existing referent because publication replaces entries. With status enabled,
all resolved referents must differ; hardlink aliases are refused. Case-only and
Unicode-normalization aliases are conservatively refused on every platform.
Tilde/relative paths expand once, anchored to the invocation directory. Atomic
writes replace a final symlink rather than modifying its target.

For event streams, a non-null `structured_output` must contain the report object;
only absent/null permits using `result`. The last terminal event is authoritative.

`--status-output /outside/repo/status.json` writes a versioned outcome without
changing the validated `--json-output` report format. Completed status values:
`scoped-clean`, `findings`, `filtered`, `incorrect`, `incomplete`. A launched reviewer
that fails or returns invalid output yields `reviewer_unavailable` (exit 1).
A failed later pass never publishes a partial report.

```json
{
  "schema_version": 1,
  "status": "reviewer_unavailable",
  "exit_code": 1,
  "engine": "codex",
  "report_produced": false,
  "reason": "engine_failed",
  "reviewer_exit_code": 124,
  "timed_out": true
}
```

Unavailable reasons: `engine_failed`, `invalid_report`, `runtime_validation_failed`;
completed reviews use null. Runtime validation means Amp's post-launch isolation
attestation/private-result check refused output, not a transient-provider failure.
`reviewer_exit_code` is the retained last process code (possibly zero for rejected
output), otherwise null. `timed_out` identifies the helper's deadline, not merely
process exit 124. Inspect status independently of `--expect-findings` exit changes.

An unfinished assessment keeps validated observations with `incomplete`, exit 2,
and `report_produced: true`, even with findings. The private completion field is
not published. Missing/invalid completion is an invalid report, not unfinished.

Status contains no logs, prompts, findings, or model identifiers. Bounded display-safe
stderr diagnostics and command-auth suppression remain enabled. Use a fresh status
path: after argument/path validation, old status is removed before target selection.
Dry runs, preflight/pre-launch isolation refusals, source mutations, interruptions,
and output failures produce no new status. Absence is never a clean verdict.

## Usage

Codex collects usage with live display on or off. Reports, status, and terminal
summary include process attempts; reported, unknown, and partial counts; `complete`;
and observed token totals. Each attempt contributes its last valid cumulative
snapshot once, including access retries and failed passes. Retry policy lives in
[engine options](engines.md).

Cached input/reasoning output are subsets, not extra totals. Counts are observed
tokens, not billing estimates or cache-hit promises. Missing telemetry (including
all-zero defaults without a sample) is unknown, never measured zero. `tokens: null`
means no usable totals; incomplete totals are lower bounds. Interrupted runs print
retained usage without publishing status/reports. Other engines do not aggregate usage.
