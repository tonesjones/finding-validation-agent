# Plan

Started 2026-10-03 from main `5b93670` (346 passed, 4 skipped). Claude leads; Opus works
inline, Sonnet runs well-specified write-heavy packages. Status lives in `CHECKPOINT.md`.

## Goal

Automated SAST/SCA triage with evidence and confidence. Nobody grades or reviews by hand:
not the owner, not the tool's users. Every automated decision must be right without a person
checking it, so accuracy of auto-routed rows outranks the share that is auto-routed. Findings
the tool cannot decide stay open (`needs_review`); they are never closed to shrink the queue.
The frozen blind pilot stays historical: no edits to its packets, prompt or demo checkout.

- **Primary target:** the demo app (record-desk) at `9ac5160`: one CWE-201 server banner
  finding and five lodash 4.17.20 SCA advisories. Rules-only leaves all six at `needs_review`.
- **Regression check:** Juice Shop, scored with `fva score` against the 570-row PoC ledger.
- **Runtime:** the collector needs the source-identity header added after `9ac5160`, so
  runtime work waits for a Polaris rescan of that later commit in a separate worktree.

## Tasks

| ID | Task | Model | Status |
|---|---|---|---|
| T1 | Housekeeping: CHECKPOINT "Next", this file, branch | Opus | done |
| T2 | Exception-routed triage core | Opus | done |
| T3 | `fva triage` outputs and score columns | Sonnet | done |
| T4 | Vulnerable-function call sites for SCA | Opus | done |
| T5 | `assess-v2` stance semantics | Opus | done |
| T6 | Collector oracles and demo runtime run | Opus | blocked on rescan |
| T7 | Ranked report and tickets | Sonnet | done |

### T2 Exception-routed triage core
`fva/triage.py` gives every finding `route = auto | review` plus exception reason codes
(appended to `fva/reason_codes.py`). Exceptions: low confidence, conflicting evidence,
model-only refutation, missing or mismatched profile, runtime evidence without verified
provenance, and a high/critical finding that would be closed or demoted. Thresholds live
in one policy table.

Done when: every `auto` row passes `check_suggestion`; one unit test per exception reason;
on Juice Shop, auto-routed incorrect demotions are 0.

### T3 Triage outputs
`python -m fva triage <run>` writes `triage.jsonl` and `triage.md` (queue size, auto counts
by reason, exception list). `fva score` gains auto-share and auto-agreement columns.

Done when: tests pass and output is byte-identical across two runs on the same run dir.

### T4 Vulnerable-function call sites for SCA
A curated advisory-to-function table beside `_RANGES` in
`fva/correlation/advisory_applicability.py`, and a Node call-site finder (`_.fn`,
destructured imports, `require('lodash/fn')`). A shipped call site supports the finding;
no call site and no dynamic access refutes it with `VULNERABLE_FUNCTION_NOT_CALLED` at
medium confidence; dynamic or unknown access is neutral.

Done when: each of the demo's five SCA findings has a call-site record; on Juice Shop no
PoC-confirmed SCA row is refuted and the 18 version-drift rows are unchanged.

### T5 `assess-v2` stance semantics
Restating the sink is `neutral`; a real quality issue is `non_security`; a cited
precondition refutation outranks a restated sink. SCA prompts carry the advisory function
and T4 call sites. New prompt version only.

Done when (revised 2026-10-03): auto-routed agreement on Juice Shop goes up with no incorrect
demotions and no new refutations of PoC-confirmed rows. Raw model-stance agreement is not the
target: a neutral answer leaves a finding open and cannot cause a wrong decision.
Result: auto-routed agreement 96.0% -> 99.3%, wrong auto `likely` 19 -> 3, auto share
82.7% -> 78.0%, incorrect demotions 0.

### T6 Collector oracles and demo runtime run
Two oracles in `fva/runtime.py`: an exact-header disclosure check for CWE-200/201 with a
control request, and an SCA marker check allowed only when T4 linked a shipped call site
to the probed route. Rejection tests first: off-allowlist target, non-GET verb, missing
call-site link, missing identity header. Then an exact plan for the operator, who runs
`runtime approve`; Claude collects and imports.

Done when: the banner and CVE-2021-23337 reach `RUNTIME_CONFIRMED` only through verified
receipts, and everything else stays open.

### T7 Ranked report and tickets
Ranking by verdict, reachability, runtime and severity. One ticket per grouped issue, no
raw receipts.

Done when: output is deterministic and every closure cites evidence ids.

## Later or blocked

- DAST: waits on entitlement.
- `--client litellm`: work laptop.
- Polaris writer (v0.8): company GitHub plus sign-off.
- Jev evaluation, multi-app benchmark, malformed-input audit, repo migration.

## Status (2026-10-03)

- Demo: 6/6 `needs_review` -> 5 auto (2 `likely` via `template` call sites, 2 closed as
  `VULNERABLE_FUNCTION_NOT_CALLED`, 1 `likely` for the toNumber ReDoS), 1 open (banner, waits on T6).
- Juice Shop (assess-v2): 78.0% auto, 99.3% auto agreement, 0 incorrect demotions.
- Model calls never close a finding; their only automated effect is promoting `needs_review`
  to `likely`. Rules close 430 of 573 Juice Shop findings with no model involvement.
- Adding reason codes changes every prompt (the prompt lists allowed codes) and empties the
  model cache; a full Juice Shop re-run is about 131 Codex calls.

## Open decisions

- `VULNERABLE_FUNCTION_NOT_CALLED` closes automatically at medium confidence only up to medium
  severity; high/critical stay open (triage `HIGH_IMPACT_CLOSURE`).
- The report should present review rows as "open, not auto-verified" rather than as a queue a
  person must work through.
- T6 needs a Polaris rescan of the demo at the source-identity commit and one operator
  `runtime approve` per collection plan (a safety gate, not grading).
