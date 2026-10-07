# Review the project data cleanup plan

Prepared October 7, 2026. Revised after review. Status: approved and in progress.

Keep the inputs and results that support the current FVA work. Archive retired experiments and delete generated test clutter. The user approved execution and chose a same-drive backup (doesn't protect against drive failure).

## What the inventory shows

Before cleanup, the local `data/` folder contained 55,365 regular files and 4,382 symbolic links. The files used about 735.6 MB across 51 run folders. Sizes use 1,048,576 bytes per MB.

The code cleanup in PR #42 removed the blind pilot, coverage, loaded-module, and research tooling. Their ignored data remains. Coverage captures account for about 79% of the folder's size.

`data/` is excluded from Git. Git cannot restore deleted inputs, model answers, approvals, or evidence.

## Back up before any move or delete

Copy `data/`, excluding `data/coverage/`, to the private same-drive backup (doesn't protect against drive failure). The regular files outside coverage use about 156 MB. The verified copy uses about 175 MB because it expands symbolic links in generated test workspaces. Include hidden files, model caches, the PoC ledger, and complete run folders.

The initial drive check showed only C:, so the selected same-drive backup (doesn't protect against drive failure) is on C:.

Pause any process that writes to `data/` while copying. Compare regular-file paths, sizes, and SHA-256 hashes. If the copy expands symbolic links, preserve and verify a manifest of their paths and targets. Keep the verified backup after cleanup. The backup contains private scanner data and credentials, so keep it private.

Coverage is the sole backup exclusion. Preserve it in the verified ZIP described below before deleting its original files.

## Keep the current inputs and evidence

| Keep in its current location | Reason |
| --- | --- |
| `data/polaris-export/` | Juice Shop scanner input. The CLI uses this location by default. |
| `data/ingestion/record-desk-static-20261003/` | Record Desk scanner exports and import checks. |
| `data/ingestion/uptime-kuma-2a4d763/` | Uptime Kuma scanner exports for the current generalization test. |
| `data/poc-report/` | Juice Shop answer key and its supporting records. Scoring and private-data tests still use them. The answer key remains LLM-driven and needs independent adjudication. |
| `data/resolved/` | The resolved Juice Shop dependency lockfile used for dependency checks. |
| `data/cache/` | About 1 MB of model answers. Keep all of it for repeat runs and comparisons. |
| `data/runs/record-desk-0f17d90-profile/` and `data/runs/uptime-kuma-2a4d763-profile/` | Deployment profiles needed to reproduce the runs. |
| `data/.polaris-token` | Local credential used by the export client. Keep private and outside archives intended for sharing. |

Keep these run folders under `data/runs/`:

| Run | What it supports |
| --- | --- |
| `20261005-js-fresh` | Current Juice Shop benchmark, scoring, and ranked report. |
| `20261005-js-rerun` | Repeatability and the zero-cost cached rerun. |
| `20261007-js-devdep` | Juice Shop regression after the dev-only dependency rule. |
| `20261005-recorddesk-fresh` | Record Desk before the advisory rule fix. |
| `20261005-recorddesk-imports` | Record Desk after the advisory rule fix. |
| `20261007-uk-fresh` | Untuned Uptime Kuma result before the dev-only rule. Its failure to reach the 50% bar matters. |
| `20261007-uk-devdep` | Uptime Kuma after the dev-only rule. Preserve the before-and-after evidence. |
| `20261004-js-merged` | Historical run cited by `docs/demo-pitch.md`. |

Keep each retained run as a complete folder. Findings, assessments, evidence, summaries, and reports together explain the result. Keep the matching source checkouts at the scanned commits outside this repository.

Keep the application code, test source, sanitized test fixtures, and `.venv/`. They are part of the working project.

## Archive the retired experiments

Create `data/archive/20261007.zip`. Preserve the original paths relative to `data/` inside the ZIP and include a short index. Archive the reviewed folders directly, without keeping a permanent uncompressed archive folder.

| Archive candidate | Size | Reason and condition |
| --- | ---: | --- |
| `data/coverage/` | 579.5 MB | Old coverage captures and receipts. Their consumer was removed. Preserve the raw evidence with the receipts. |
| `data/loaded/` | 7.5 MB | Old loaded-module experiment. Archive with coverage. |
| `data/dast-fva-scans/` | 56.4 MB | Old build contexts, source ZIP, downloads, scan scripts, and research. DAST is parked. |
| Other `data/dast-*` folders and `data/runtime/` | Small | Historical scan attempts, correlation work, and runtime evidence. Keep complete records. |
| `data/eval/` | 1.5 MB | Retired blind-pilot work. Preserve frozen cases, labels, receipts, raw responses, and audits together. |
| `data/polaris-export-fva/` | 2.2 MB | Historical scanner exports. No code outside `data/` refers to this location. Preserve the exports in the ZIP. |
| Older folders in `data/runs/` | Runs total 50.6 MB | Smoke calls, dry runs, routing comparisons, and earlier rule experiments. Review references before moving each folder. Exclude the retained runs above. |
| Old PR-body drafts and session prompts in `data/` | Small | Historical working notes. Archive after extracting any useful current instructions. |

The coverage decision is to compress and retain the captures, then delete their uncompressed originals. The code that consumed them was removed in PR #42.

Before deletion, reopen the completed ZIP and decompress every entry to verify it. Compare each entry's size and SHA-256 hash with the original file. Merely listing ZIP entries is insufficient. Delete originals only after the archive passes these checks.

The first three candidates contain about 643 MB before compression. Measure the completed ZIP to determine the actual space saving. Do not promise a compression ratio. Keep any temporary extraction outside `data/` and remove it after verification.

Leave compatibility samples and analysis folders in place until their references and provenance are checked. They have not been confirmed as redundant.

## Delete generated test clutter

The inventory found 44 `data/pytest-*` folders and 6 `data/pr9-submodule-*` folders. Together they contain about 32.8 MB, not the 1.5 MB reported by the earlier restricted inventory. These are generated test and reproduction workspaces.

Before deletion, confirm that no test or reproduction session uses them and that they contain no unique source edits or evidence. Delete only the reviewed paths. Do not apply these patterns to the repository's `tests/` folder.

Earlier Codex session commands explicitly passed `--basetemp=data/pytest-dast-fva-20261005-01` and similar paths. That explains at least some of the folders. The current repository, pytest configuration, and CI do not set a temporary directory under `data/`. The origin of every folder has not been traced.

Use pytest's default temporary directory for future runs. If a sandbox requires an explicit `--basetemp`, use an allowed scratchpad or system temporary directory dedicated to that run. Confirm the directory is writable first. Never use `data/` or a shared temporary root as `--basetemp`, because pytest clears its base directory.

Add this instruction to `CLAUDE.md` and future delegation prompts through the separate documentation PR below. Do not add a test wrapper or configuration system.

Python `__pycache__/` folders and `.pytest_cache/` are also disposable. Removing them is optional because the space saving is small.

## Keep documentation changes in a separate PR

The local data cleanup does not use Git. Publish tracked documentation changes on a separate branch, `codex/data-cleanup-docs`, with their own PR into `main`. Review and verify that PR independently of archive and deletion checks.

This plan can remain in `docs/` for the PR. It names local paths and runs but contains no credential values or tenant identifiers. Keep raw inventory details and backup locations private.

| Document | Proposed change |
| --- | --- |
| `data/next-session-prompt.md` | Archive. It points to deleted checkpoints and plans and describes superseded work. |
| `data/LOCAL-NOTES.md` | Keep the current Polaris identifiers in a short local note. Archive the historical checkpoint narrative. |
| `ROADMAP.md` | Align its next steps with the October 7 status. Uptime Kuma has run, specific missing-evidence text has shipped, Habitica is next, and clean-machine setup is deferred. |
| `PLAN.md` | Reconcile unchecked items with recorded completed runs and checks. Preserve the failed Uptime Kuma result and the remaining Definition of Done gaps. |
| `CLAUDE.md` | Direct future test runs and delegation prompts to default temporary storage or a dedicated allowed scratchpad. Prohibit `--basetemp` under `data/`. |
| `docs/demo-pitch.md` and `docs/experiments/001-juice-shop.md` | Keep as dated records. Keep their distinction from current results. |

Use [STATUS.md](../STATUS.md) and [PLAN.md](../PLAN.md) to resume current work.

Changes to `data/LOCAL-NOTES.md` and the old session prompt remain local data work. They do not belong in the documentation PR.

## Execute local cleanup after approval

1. Refresh the inventory and compare it with this plan.
2. Confirm the retained runs, inputs, profiles, caches, and source checkouts.
3. Create and verify the same-drive backup (doesn't protect against drive failure), excluding coverage.
4. Save the current `20261005-js-fresh` score and report outputs for comparison.
5. Check references before archiving any old run or export folder.
6. Create `data/archive/20261007.zip` from the reviewed candidates.
7. Reopen the ZIP and verify every decompressed entry against the original files.
8. Delete the verified archive originals, including `data/coverage/`. Keep the ZIP.
9. Delete the reviewed generated test workspaces.
10. Shorten local notes and archive the superseded local session prompt.
11. Rerun scoring and report generation using the retained Juice Shop run.
12. Compare outputs with the saved baseline and record actual disk savings.

Do not launch scans, probes, or model calls as part of cleanup. Any folder with unresolved references stays in place.

Use the repository's virtual environment for the final check:

```powershell
.\.venv\Scripts\python.exe -m fva score data/runs/20261005-js-fresh
.\.venv\Scripts\python.exe -m fva report data/runs/20261005-js-fresh
```

Require the regenerated `score.md` to match the saved copy. Compare `score.json`, `tickets.jsonl`, `report.md`, and `report.html` as well. Investigate any difference before reporting completion. These commands use saved assessments and evidence, so they need no model calls.

If baseline comparison fails, keep the verified backup and ZIP and restore the affected inputs before retrying. Do not discard recovery copies.

To refresh the file count and size, run this read-only command from the project root:

```powershell
Get-ChildItem -LiteralPath data -Recurse -Force -File |
	Measure-Object -Property Length -Sum
```

## Review decisions

- [x] Keep the listed inputs, complete runs, profiles, and model caches.
- [x] Create and verify the same-drive backup (doesn't protect against drive failure) before cleanup.
- [x] Compress the reviewed experiments into `data/archive/20261007.zip`, verify every entry, and delete the uncompressed originals.
- [ ] Delete reviewed generated test workspaces.
- [x] Verify retained scoring and report outputs against the saved baseline. `score.md` and `score.json` match. The other outputs differ only in the newer `missing_evidence` text.
- [x] Handle tracked documentation and test-location guidance in a separate branch and PR. PR #49 is open.

## Execution status

The archive, baseline outputs, and backup were verified before any archived originals were removed. The shortened local note and archived session prompt remain local data changes.

The generated test workspaces remain in place because Windows denied the Modify permission needed to remove them. PR #49 is open for review.
