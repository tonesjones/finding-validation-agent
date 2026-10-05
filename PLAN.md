# Plan

## Authenticated DAST follow-up stopped (2026-10-05)

The isolated target, non-admin local login and identical settings artifact
read-back passed. One active scan was accepted and cancelled at approximately
15 minutes with zero target traffic and zero exported issues. The zero-issue
stop rule applies; native authentication and active coverage remain unproven.
No new assessment ran (fresh assessment cost $0.00000). Baseline auto share 83.8%,
auto agreement 99.4%, incorrect demotions 0/0 and link counts 0/0/0 are unchanged;
precision remains undefined for every tier. Scan cost was not measured.
See [the attempt and evidence limits](docs/plans/dast-authenticated.md).

## DAST FVA plan completed (2026-10-05)

D0-D6 in `docs/plans/dast-fva-app.md` passed on `codex/dast-fva`, following the
owner-authorized API scan prerequisite. SAST/SCA/DAST completed against local
Juice Shop commit `15b4641`; 357 runtime source files matched, with zero missing.
The private Docker runtime and tunnel were stopped. No hosted target probing ran;
active attacks were disabled. Raw IDs, receipts and exports remain ignored.

| Measurement | FVA result | Baseline `20261004-js-merged` | Change |
|---|---|---|---|
| Findings | 518 SAST + 56 SCA + 11 DAST = 585 | 573 | Different population |
| Auto share | 83.8% | 84.8% | -1.0 percentage point |
| Auto agreement | 99.4% | 99.4% | Unchanged |
| Incorrect demotions (all / auto) | 0 / 0 | 0 / 0 | Unchanged |
| Overall agreement | 86.9% | 86.5% | +0.4 point; coverage differs |
| Label coverage | 564/585 | 570/573 | DAST has no key labels |
| SAST-to-DAST precision, high / medium / low | Undefined / undefined / undefined | No DAST | Zero links in every tier |
| Fresh assessment cost | $0.00000; all 87 clusters cached | Not compared | Historical priced cache cost $0.16134 is partial |

All 11 DAST rows remain `needs_review`; no static confirmation or closure comes
from DAST and no row is `confirmed`. The current static-only rows have 490/574
auto (85.37%); including DAST gives 490/585 (83.76%), a 1.61-point decrease.
Do not interpret undefined link precision as perfect precision or differing
baseline agreement as a DAST accuracy gain. Active-attack value remains unmeasured.

Assessment used four workers and the existing Luna bulk / Sol sensitive and
`supports` escalation routing; cached attempt metadata identifies 51 Luna and
46 Sol attempts. No fresh model calls or subscription savings claims were made.
Real-envelope mapping preserves all 11 scanner IDs, drops target hosts, redacts
text and adds no reason codes. Score/report/SARIF completed with 11 DAST results.
Windows: 658 passed, 5 skipped. Linux: 657 passed, 6 skipped.

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
| T6 | Collector oracles and demo runtime run | Codex + Opus review | done (banner); CVE-2021-23337 not probed |
| T7 | Ranked report and tickets | Sonnet | done |
| T8 | More closing rules; "open, not auto-verified" wording | Opus | done |

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
Result (2026-10-04, `docs/plans/runtime-pilot.md`): the banner reached `RUNTIME_CONFIRMED` through a verified
`header_disclosure` receipt; the other five findings kept their verdicts. The owner chose not to probe
CVE-2021-23337, so it stays `likely` as a fix ticket.

### T7 Ranked report and tickets
Ranking by verdict, reachability, runtime and severity. One ticket per grouped issue, no
raw receipts.

Done when: output is deterministic and every closure cites evidence ids.

### T8 More closing rules and report wording
Rules that close findings with no model call: Polaris quality checker `no_effect` -> `QUALITY_NOT_SECURITY`
(keyed on the checker, not CWE-398, which also covers `copy_paste_error`); sanitize-html advisories whose GHSA
names a non-default option (`allowedAttributes` with style, `allowedIframeHostnames`, `transformTags`,
textarea/xmp in `allowedTags`) -> `ADVISORY_PRECONDITION_ABSENT` when no shipped call passes it, any non-literal
options or other use stays neutral; GHSA ranges for six sanitize-html advisories. Both closures are medium
confidence, so high/critical stay open. Reports say "open, not auto-verified" instead of "review", and a closure
that triage did not auto-route is reported open, not closed.

Done when: Juice Shop auto share rises with auto agreement not lower, 0 incorrect demotions, 20 version-drift
rows unchanged, every new closure agrees with the PoC key.
Result: auto share 78.0% -> 84.8%, auto agreement 99.3% -> 99.4%, 0 incorrect demotions, 0 model calls
(all cached); 32/32 `no_effect` and 6/6 scored sanitize-html closures agree.

Follow-up plan (2026-10-04): `docs/plans/unblocked-backlog.md`.

## Later or blocked

- DAST: waits on entitlement.
- `--client litellm`: work laptop.
- Polaris writer (v0.8): company GitHub plus sign-off.
- Jev evaluation, multi-app benchmark, repo migration. The malformed-input audit moved to the follow-up plan.

## Status (2026-10-03)

- 2026-10-04: merged into main through `claude/integrate-triage-exceptions`. The Juice Shop numbers below
  reproduce on main (`20261004-js-merged`).

- Demo (assess-v2 + T8): 3 auto (CVE-2021-23337 `likely` via the `template` call site, 2 closed as
  `VULNERABLE_FUNCTION_NOT_CALLED`), 3 open: the banner (waits on T6), CVE-2020-28500 (lodash calls toNumber
  internally, so no call-site rule), CVE-2026-4800 (high; the model correctly notes no `imports` option, but a
  medium-confidence rule could not close a high finding). The earlier "5 auto" was the v1 prompt.
- Juice Shop (assess-v2 + T8): 84.8% auto, 99.4% auto agreement, 0 incorrect demotions.
- T6 oracle code is merged. Codex wrote the oracles and rejection tests; Claude's review added the Express
  `X-Powered-By` framework default (the demo banner has no literal in source) and stopped later receipt
  verification from re-reading the checkout. The live run is done (2026-10-04): the banner is confirmed by a
  verified receipt, so the demo decides 4 of 6 automatically.
- Model calls never close a finding; their only automated effect is promoting `needs_review`
  to `likely`. Rules close 430 of 573 Juice Shop findings with no model involvement.
- Adding reason codes changes every prompt (the prompt lists allowed codes) and empties the
  model cache; a full Juice Shop re-run is about 131 Codex calls.

## Open decisions

- `VULNERABLE_FUNCTION_NOT_CALLED` closes automatically at medium confidence only up to medium
  severity; high/critical stay open (triage `HIGH_IMPACT_CLOSURE`).
- Each runtime collection needs one operator `runtime approve` for its exact plan (a safety gate,
  not grading). T6 reused the `9ac5160` scan against the `0f17d90` clone instead of a rescan.
