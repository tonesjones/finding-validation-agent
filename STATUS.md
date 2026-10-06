# Status

Updated 2026-10-05.

## Current state

FVA checks Polaris SAST and SCA exports against matching source.
It closes findings only with cited evidence and ranks the rest with missing evidence.
DAST is parked. There is no routine human review. Open findings stay open.

## Validation results

- Fresh Juice Shop run `20261005-js-fresh` covered 573 findings.
- Auto share 0.841. Auto agreement 0.996. Incorrect demotions 0.
- Model calls 101. List-price cost $0.86.
- Cached rerun cost $0 with identical verdicts on all 573 findings.
- The Juice Shop answer key is LLM-driven and needs independent adjudication.
- Record Desk had 6 findings, with 1 SAST and 5 SCA, on a fresh cache.
- Before the fix, 4 of 6 were auto-decided. GPT-6.1 Sol agreed on 3 of the 4 against redacted source.
- Both auto-closures held. PR #44 fixed an over-flag on lodash CVE-2026-4800 with an option precondition.
- After the fix, 3 of 6 are auto-decided. The imports closure stays open with `HIGH_IMPACT_CLOSURE`.
- Six findings are thin evidence. A larger real app is the stronger test.
- PR #45 gives every open ticket `missing_evidence`. Of 73 Juice Shop tickets, 50 get a generic SAST sentence.

## Standing decisions

- Use default Luna/Sol routing. Escalate Luna `supports` results to Sol.
- Polaris is the only scanner input. Focus on SAST and SCA.
- Require `--profile-file`. There is no default lockfile.
- Keep open findings open without routine sign-off.

## Next, in order

1. Delivery to a security team. The owner handles this.
2. A larger real second app.
3. A clean-machine setup test from the README alone.
4. Specific SAST gap sentences.

See [PLAN.md](PLAN.md) for each Definition of Done check.
