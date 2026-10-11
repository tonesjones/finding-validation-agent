# Polaris findings validated in the Juice Shop demo

As of 2026-10-10. This is a dated record. See [STATUS.md](../STATUS.md) for current results.

Measured 2026-10-10 on OWASP Juice Shop 20.2.0 on the safety-fix branch, with cached model answers ($0). The source
is pinned by content hash and the scan is Polaris SAST plus SCA. Every number below comes from
`python -m fva score`, `triage` and `report`. Grading uses the LLM-built PoC answer key of 570 findings.
The key needs independent adjudication.

## What Polaris hands a team

573 findings. Connected findings fold into 499 issues.

## What FVA does with them

| | Findings | Share |
|---|---|---|
| Decided automatically | 463 | 80.8% |
| of which closed | 449 | 78.4% |
| of which fix tickets (`likely`) | 14 | 2.4% |
| Open, not auto-verified | 110 | 19.2% |

The automatic decisions agree with the answer key 99.4% of the time. None of them closes or demotes a finding
the key calls real (0 incorrect demotions). Queue reduction is 0.789.

Rules made the closures, not a model. One of these 450 rule closures is a high-impact finding, so it stays open:

| Reason | Findings |
|---|---|
| Test-only code (`TEST_ONLY`) | 273 |
| Non-executable fixture (`NON_EXECUTABLE_FIXTURE`) | 94 |
| Deployment config this deployment does not use (`UNUSED_DEPLOYMENT_CONFIG`) | 41 |
| Code-quality checker, not a vulnerability (`QUALITY_NOT_SECURITY`) | 32 |
| The advisory's option is never set in shipped code (`ADVISORY_PRECONDITION_ABSENT`) | 7 |
| Documentation or API spec (`DOCUMENTATION_ONLY`) | 2 |
| Installed version outside the advisory range (`ADVISORY_VERSION_MISMATCH`) | 1 |

`fva report` turns what is left into 74 open issues and 425 closed. 13 open issues are fix tickets (`likely`) and 61 are
`needs_review`. Each one lists every original Polaris finding id it covers and the evidence ids behind it.

## What changed since the 2026-10-04 record

Auto share fell from 0.843 to 0.808, and open issues rose from 73 to 74. The drop is 20 findings. The old
`VERSION_DRIFT` rule closed them whenever the installed version differed from the scanned one, without checking that the
installed version was unaffected. They now stay open and go to assessment. 19 model clusters for them await fresh model
answers, so this is not yet a final DoD 2 number.

Other safety fixes in the same branch:

- Full-prompt and cache/log redaction.
- Model CLIs run with tools off and a minimal environment.
- Dev-only closure is blocked when an npm script runs the package.

## Checks on the closures

- Every closure cites evidence records, and code checks those records before the closure is shown
  (`fva/invariants.py`).
- A model never confirms and never closes. It can support a `likely` verdict only with
  a rule-derived record and a citation verified against the pinned source. Only redacted code
  goes to a model.
- A closure that would demote a high or critical finding without high-confidence rule evidence stays open
  (`HIGH_IMPACT_CLOSURE`).

## Limits

- The answer key is LLM-built and not independently adjudicated.
- Nothing is `confirmed` without runtime evidence. Runtime probes and DAST are parked.
- Generalization to an untuned app (DoD 3) is still open. Node-RED 5.0.8 is next.
- Quality-checker closures (`QUALITY_NOT_SECURITY`, 32) are under review, because a no-effect statement can be a
  security bug.

Open findings stay open. There is no routine human review or worksheet re-import.
