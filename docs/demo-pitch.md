# Polaris findings, validated: the Juice Shop demo

Measured 2026-10-04 on OWASP Juice Shop 20.2.0. The source is pinned by content hash and the scan is Polaris SAST
plus SCA. Every number below comes from `python -m fva score`, `triage` and `report` on runs
`20261004-js-merged` and `20261004-js-merged-passive`. Grading uses the PoC answer key, 570 findings that people
validated by hand.

## What Polaris hands a team

573 findings. Connected findings fold into 499 issues. Polaris shows no triage history for this project: all 573
issues are `not-dismissed` with dismissal reason `unset`. So nobody has triaged these findings yet.

## What FVA does with them

| | Findings | Share |
|---|---|---|
| Decided automatically | 486 | 84.8% |
| of which closed | 469 | 81.8% |
| of which fix tickets (`likely`) | 17 | 3.0% |
| Open, not auto-verified | 87 | 15.2% |

The automatic decisions agree with the answer key 99.4% of the time. None of them closes or demotes a finding
the key calls real (0 incorrect demotions). Across all 573 findings, agreement with the key is 86.5%. The
difference is the 87 findings FVA leaves open on purpose.

Rules made the closures, not a model:

| Reason | Findings |
|---|---|
| Test-only code (`TEST_ONLY`) | 273 |
| Non-executable fixture (`NON_EXECUTABLE_FIXTURE`) | 94 |
| Deployment config this deployment does not use (`UNUSED_DEPLOYMENT_CONFIG`) | 41 |
| Code-quality checker, not a vulnerability (`QUALITY_NOT_SECURITY`) | 32 |
| Installed version differs from the one flagged (`VERSION_DRIFT`) | 20 |
| The advisory's option is never set in shipped code (`ADVISORY_PRECONDITION_ABSENT`) | 6 |
| Documentation or API spec (`DOCUMENTATION_ONLY`) | 2 |
| Installed version outside the advisory range (`ADVISORY_VERSION_MISMATCH`) | 1 |

`fva report` turns what is left into 73 ranked open issues. 16 are fix tickets and 57 need review. Each one
lists every original Polaris finding id it covers and the evidence ids behind it.

## Why a team can trust the closures

- Every closure cites evidence records, and code checks those records before the closure is shown
  (`fva/invariants.py`).
- A model never confirms and never closes. Its only automated effect is to argue a finding up to `likely`, and
  even that needs a rule-derived record and a citation verified against the pinned source. Only redacted code
  goes to a model.
- A closure that would demote a high or critical finding without high-confidence rule evidence stays open
  (`HIGH_IMPACT_CLOSURE`).

## What would move the remaining 87

| Open findings | Blocker | What would help |
|---|---|---|
| Stance questions, such as whether attacker input reaches the sink | Reasoning the rules cannot settle | Additional evidence; otherwise the finding stays open, not auto-verified |
| Exploitability | No dynamic evidence in this tenant | A Polaris DAST scan of the same deployment, or an operator-approved localhost probe |
| A queue without labels | No dismissals or triage history in Polaris | Triage history in the Polaris API, so past decisions become labels |
