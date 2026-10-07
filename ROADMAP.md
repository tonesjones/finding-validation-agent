# Roadmap

FVA checks Polaris SAST and SCA exports against matching source.
It closes what cited evidence proves does not apply and ranks the rest with missing evidence.
See [PLAN.md](PLAN.md) for completed work and the Definition of Done.

## Next, in order

1. Deliver an output to a security team. The owner handles this.
2. Run Habitica as the next untuned app. The owner needs a Polaris SAST and SCA scan on a pinned commit.
3. Consider a CWE-476 code-quality rule only if Habitica shows the same null-value noise.

## Current evidence

- Uptime Kuma's fresh-cache run auto-decided 56 of 265 findings (21%). That missed the 50% bar.
- The dev-only rule raised the share to 64 of 265 (24%). It was tuned on Uptime Kuma, so Habitica remains the next untuned evaluation.
- CWE-specific missing-evidence text shipped. The generic SAST sentence fell from 52 to 6 of 73 open Juice Shop tickets.
- The clean-machine setup test was deferred on 2026-10-07. DoD 1 remains open.

## Later (explicitly not now)

Active runtime probes, SAST-to-DAST linking, Polaris write-back, more advisory call sites,
other languages, a multi-app benchmark and Jev.
The company GitHub move and LiteLLM client gate real customer data.
