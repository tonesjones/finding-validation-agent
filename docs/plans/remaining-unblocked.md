# Plan: remaining unblocked work

Started 2026-10-04 after `docs/plans/unblocked-backlog.md` finished. Owner: "do everything" on the
five items below. Out of scope as before: DAST (entitlement), `--client litellm`, the Polaris writer,
Jev, the multi-app benchmark, expert grading, the repo move.

Branches stack on `claude/cost-smoke-evidence` (PR #32) until it merges, then rebase onto `main`.

| # | Item | Branch | Model | Fresh Codex calls |
|---|---|---|---|---|
| 1 | Bring ROADMAP and the CHECKPOINT backlog in line with the code | `claude/remaining-unblocked` | Sonnet checks, Opus edits | none |
| 2 | Record versions for reproducibility in `summary.json` | `claude/remaining-unblocked` | Opus (small) | none |
| 3 | Enriched SARIF export, SAST and SCA (DAST when it exists) | `claude/sarif-export` | Sonnet builds, Opus reviews | none |
| 4 | Polaris triage and comment preview (dry run, writes nothing) | `claude/polaris-preview` | Sonnet builds, Opus reviews | none |
| 5 | One fresh full Juice Shop run to measure Codex's prompt-cache hit rate | results in this file | none (a run) | about 131, approved |

## 1. ROADMAP and backlog

Acceptance:
- Each unticked ROADMAP item and each open CHECKPOINT backlog item is checked against the code. An item is
  ticked only with a pointer to the module or test that does it; partial items say what is missing.
- No item is ticked on the strength of a plan or a CHECKPOINT note alone.

## 2. Versions

`summary.json` already has the model, `prompt_version` and the source hash. It gains a `versions` block:
FVA package version, FVA git commit and whether the tree was dirty, Python version, platform, the
reason-code vocabulary size, and the Codex CLI version when the client is `codex`.

Acceptance:
- A missing `git` or `codex` gives `null`, never a failed run.
- The cache key is unchanged (the pinned key test passes).
- Nothing in the block is a path, user name or token.

## 3. Enriched SARIF export

`python -m fva sarif data/runs/<run>` writes `sast.sarif` and `sca.sarif` (and `dast.sarif` when the run has
DAST findings): SARIF 2.1.0, one result per original finding, scanner ids byte-for-byte, each result's
properties carrying the fva verdict, triage route, reason codes, issue id and evidence ids, types, stances and
methods. Like tickets, no evidence summaries or `detail_ref`.

Acceptance:
- Each file parses back with `fva.adapters.sarif.parse` and keeps every scanner id.
- Same run directory, same bytes.
- Tests on sanitized fixtures only; a test checks no evidence summary text appears in the output.
- Nothing claims Polaris accepts the file; Polaris import is unverified.

## 4. Polaris preview

`python -m fva preview data/runs/<run>` writes `preview.jsonl` and `preview.md`: for each Polaris issue
whose suggested triage differs from its current one, the current status, the suggested status and severity
(`fva/export/polaris_triage_map.py`), and the comment a writer would post (verdict, reason codes, evidence ids).
Only auto-routed rows get a change; review rows are listed as "no change, open". Every row has
`approved: false`.

Acceptance:
- No network, no import of `fva.polaris_mcp`; a test enforces it.
- The header says the label map is ASSUMED and nothing was written.
- Comments carry no evidence summaries or receipt content.

## 5. Fresh run

`assess --workers 4` with an empty cache directory in the scratchpad (the main cache is untouched), into
`data/runs/20261004-js-fresh-cost`, then `score` and `triage`.

Acceptance:
- The `cost` block gives real fresh-call usage and dollars per tier; the cache hit rate is recorded here and
  in CHECKPOINT.
- Score and triage are compared with `20261004-js-merged`. Differences are reported, not tuned away.

## Results (2026-10-04)

Item 1: `ROADMAP.md` now ticks only what code and tests show, with a pointer each; partial items say what
is missing. CHECKPOINT backlog items 1 (stance semantics) and 3 (SCA prompt contents) are done; 5 is partial.

Item 2: `summary.json` has a `versions` block. Fresh Codex calls also fill the old `tokens` stat again: `--json`
had dropped the footer it came from, so it is now rebuilt from the usage event (uncached input plus output).

Items 3 and 4: PR #33 (`fva sarif`) and PR #34 (`fva preview`).

Item 5: `data/runs/20261004-js-fresh-cost`, 93 clusters, 97 fresh calls (4 low-confidence escalations), 0 errors,
6 minutes with 4 workers.

| | Luna | Sol | Total |
|---|---|---|---|
| Fresh calls | 57 | 40 | 97 |
| Codex prompt-cache hit rate (cached / input tokens) | 64.0% | 74.1% | 68.2% |
| Average input / output tokens per call | 23,488 / 190 | 23,633 / 333 | |
| Cost per call at list prices | 0.109 cents | 1.91 cents | |
| Run cost at list prices | $0.062 | $0.763 | $0.825 |

The earlier warm-cache estimate (Sol 1.24 cents, about 88% cached) was optimistic: a real run caches about 68%.
A direct API client would cost about $0.45 for the same calls (our ~3.6k tokens uncached per call), so it saves
about 46%, $0.38 per fresh run. That is still small next to moving the spend off the subscription.

Against the cached baseline `20261004-js-merged` (same code, same prompts, answers from earlier calls):

| | Baseline | Fresh |
|---|---|---|
| Auto share | 84.8% | 84.8% |
| Auto agreement | 99.4% | 98.8% |
| Overall agreement | 86.5% | 85.8% |
| Incorrect demotions | 0 | 0 |
| Over-flags | 1 | 4 |

9 rows changed, 8 of them on Luna answers. 4 rows the baseline routed auto as `likely` went back to review: 3 the
key confirms (`routes/login.ts:61-62`, credentials, and `routes/profileImageUrlUpload.ts:24`, a Sol answer) and the
baseline's one over-flag (`server.ts:183`). One review row changed verdict but stayed in review. 4 rows went to
`likely` and auto, and the key disagrees with all 4: two hard-coded credentials it calls inactive (`routes/changePassword.ts:19`, `routes/resetPassword.ts:26`),
a null dereference it calls non-security and an insecure link target it calls mitigated. These are over-flags
(tickets), not wrong closures.

This weakens the item 1 credential evidence from the earlier plan: on fresh answers `ask` gives 3 correct and 2 wrong
credential `likely` rows, not 5 correct. A single Luna `supports` plus a static reachable sink is enough to route
`likely` automatically. Options for the owner, not built: send model-backed `likely` from Luna to Sol before it
auto-routes, or route model-backed credential `likely` to review. The `ask` default is unchanged.

Decision (owner, 2026-10-04): a Luna `supports` escalates once to Sol, and Sol's answer replaces it
(`fva/reasoning/routing.py`). Measured on the baseline's cached answers (`data/runs/20261004-js-sol-supports`, 6 fresh
Sol calls, $0.16): Sol backed 3 of the 6 Luna `supports` and answered neutral on 3, all `routes/login.ts` credentials
the key confirms. Auto share 84.8% to 84.3% (486 to 483), auto agreement 99.4% in both, 0 incorrect demotions,
over-flags 1 in both. On these answers the rule costs 3 correct automatic decisions and fixes none. The baseline's
Luna `supports` were all right. The case it targets is the fresh run's 2 credential over-flags, and that is not
measured: it needs 7 more Sol calls on the fresh run's answers.

## Status

- 2026-10-04: all five items done. PRs #33 and #34 open; this branch holds items 1, 2 and 5.
