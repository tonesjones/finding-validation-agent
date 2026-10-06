# Status

Updated: 2026-10-05.

## Current state

The pipeline focuses on SAST and SCA findings. DAST is parked. Findings without enough evidence stay open.

## Measured results

Juice Shop runs `20261004-js-sol-supports-guard` and `20261004-js-fresh-sol-guard` each had zero incorrect demotions. Auto share was 0.838 and 0.836; auto agreement was 0.996. A fresh run costs about $0.83.

## Standing decisions

- Use the default Luna/Sol routing policy.
- Escalate Luna `supports` results to Sol.
- Keep DAST parked; focus on SAST and SCA.
- Open findings stay open; there is no routine human review.

## Next

See [PLAN.md](PLAN.md) for the remaining work.
