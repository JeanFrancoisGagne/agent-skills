# Git collection and context

## Git collection

Registered nested linked checkouts from the same repository are outside the
current review scope. Their presence or edits do not make the parent dirty;
ordinary adjacent files remain included in the review. Worktree boundaries are
revalidated without changing Git ignore rules.

Git display settings cannot suppress context markers or add patch colors;
repository configuration is not changed. Source paths and text retain literal
whitespace. An empty present source uses line 1, column 1, and an empty excerpt; empty physical lines also
use an empty excerpt at column 1. Source identity remains mandatory.

Binary deletions remain in scope as Git deletion metadata; their former contents
are not included or reviewed. Each local transition is checked independently:
deleting a file in the working tree cannot hide a staged binary change.

Finding locations may use native absolute paths that resolve inside the reviewed
repository; these become repository-relative paths before scope and attribution
checks, preserving a changed symlink's path when its target is also inside.
Parent traversal and paths resolving outside the repository remain invalid.
An invalid location still fails the report; findings are never silently dropped.

Local selection honors `core.autocrlf` from external operator Git configuration,
with repository-local values and attributes retaining precedence. Only its
validated scalar value reaches diff/status; other global and system Git
configuration stays disabled. Repository-owned or relative global-config
overrides are not imported, and reviewed source bytes are not rewritten.

Local collection disables effective Git clean/process commands and requires
conversion to succeed. Unused drivers, unchanged filtered neighbors, staged-only
changes, and deletions can still be reviewed without executing converters.
If Git needs executable conversion to assemble the diff, collection fails before
any reviewer starts. This can include an unchanged filtered file whose stat cache
needs refreshing. Use explicit branch or commit mode for committed content in
that case. Built-in line-ending normalization remains enabled; raw bytes never
stand in for a required executable conversion.
PR-base discovery uses trusted external Git and a scoped GitHub CLI environment,
preserving external authentication/configuration and proxy settings while excluding
inherited Git routing, `GH_REPO` redirection, and checkout-owned executables.
A differently named `AUTOREVIEW_GIT` override that cannot also be selected as `git`
by the child requires an explicit `--base`; rejected GitHub configuration paths
also require one.

## Committed source context

Basic context flags and safety rules live in [SKILL.md](../SKILL.md#context-and-severity).
Repeated paths in the same evidence role share one validated capture. Equal
content at different paths and prompt-file versus dataset roles stay distinct.

For unchanged committed source, use repeatable `--source-context <repo-relative-path>`
with branch or commit mode. Use `--source-context-file <repo-relative-path>` when
that source must stay intact in every review pass. Both read the exact regular-file
blob from the frozen reviewed commit (branch HEAD or `--commit`), including executable source files.
Local mode, including an auto-selected local target, is unsupported. No separate
context revision or working-copy substitution is accepted. The checkout path must
remain a regular file; its bytes and path topology are revalidated throughout review.
Repeated normalized source-context paths share one capture after every argument
is validated; different paths and evidence roles remain distinct.

Both roles use tracked-source filename classification, so source names such as
`src/token_count.py` are accepted. Credential directories, stores and keyfiles
remain forbidden. Existing prompt-file and dataset restrictions are unchanged.
Every source block carries path, commit, blob and mode provenance. `--source-context`
bytes are partitioned with the change when needed. `--source-context-file` blocks
stay complete in every pass and must fit with the instructions and change framing;
the helper refuses an over-capacity plan without dropping required evidence.
Context never adds finding targets or instruction authority. This is a
source-provenance contract, not secret-content scanning.

```bash
"$AUTOREVIEW" --mode branch --base origin/main --source-context src/token_count.py
"$AUTOREVIEW" --mode branch --base origin/main --source-context-file src/token_count.py
```

## Runtime diagnostics

Before repository detection or target selection, Git must pass `--version`
within 10 seconds. Failure exits `2` with an `incomplete` diagnostic and the
resolved executable (or the unresolved selection); it never means `scoped-clean`.
Executable discovery skips inaccessible search candidates; an inaccessible
explicit executable override still fails preflight.
Set `AUTOREVIEW_GIT` to a trusted external Git executable to override every
helper-owned Git invocation. On macOS with a broken selected Xcode, use
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` for the invocation.
Only an absolute, external `DEVELOPER_DIR` is additionally retained in Git's
sanitized environment;
neither override is forwarded to the isolated reviewer environment.

## Partition planning

Text review files have no size/count cap and are never truncated; image inputs
use the [image safety limits](images.md). Large diffs and
datasets are partitioned automatically. Change partitions retain complete
datasets when they fit with sufficient change space. This preference may use more
passes or prompt bytes than evidence batching; the explicit pass budget still applies.
Terminal fallbacks preserve a feasible complete-evidence plan when batch framing cannot fit.
Intact instructions, source-context files and required mixed source context must
fit the per-pass prompt budget. A failed pass does not produce a partial clean verdict.
Otherwise, the planner compares a bounded set of evidence allocations and keeps the existing
plan unless total prompt bytes improve without more passes, or equal bytes need
fewer passes. Every change is still reviewed against every evidence batch.
