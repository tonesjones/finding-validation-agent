# Status

Updated 2026-10-11.

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
- PR #45 gives every open ticket `missing_evidence`. CWE-keyed SAST sentences cut the generic ones from 52 of 73 to 6.
- Uptime Kuma `2a4d763` (265 findings, untuned) auto-decided 21%, below the 50% bar. $2.21.
  All 56 auto-closures were path rules; 55 hold. Models and dependency rules closed nothing. See PLAN.md.
- The dev-only dependency rule closes a lockfile `dev` package only when no non-test file references it
  or a package that depends on it. Uptime Kuma: 16 more closures (8 auto), all correct. Juice Shop unchanged.

- Codex tool features are now off and canary-checked (`check-isolation`, passed on codex-cli 0.157.1).
  Codex stays for personal testing. Company use goes through a model gateway: `fva setup` (LiteLLM URL,
  model per tier) is done; Polaris, source and a one-command run are next (PLAN.md, "Work setup").
- Astra review (2026-10-10) safety fixes, PRs #50-#53:
  - version drift no longer closes;
  - full prompt, cache and log redaction;
  - dev-only blocked by npm scripts;
  - model CLIs with tools off and a minimal environment.
- Juice Shop cache-only check `20261010-js-phasea2` (all four PRs, $0, cached Codex answers): auto share 0.808,
  auto agreement 0.994, 0 incorrect demotions, queue reduction 0.789, 74 open issues.
  - Main before the fixes (`20261010-js-main`) was 0.843. The drop is the 20 old drift closures.
- DoD 2 rerun `20261011-js-dod2` (2026-10-11, main `84279a6`, fresh Codex answers for the 19 drift clusters):
  auto share 0.808, auto agreement 0.994, 0 incorrect demotions, queue reduction 0.789. 112 clusters,
  19 fresh calls, 0 errors, $0.46 list price. DoD 2 still passes. The drift findings stayed open.
- F6 (PR #56): a `no_effect` finding closes only on an explicit discard (`void`, `??=`). All 32 Juice Shop
  closures match, so the numbers above are unchanged.
- Node-RED 5.0.8 (`935b8d3e`) fits DoD 3: npm v3 lockfile, no workspaces, `red.js` entry, and `adminAuth`
  roles `*`, `read` and `default`. Profile drafted in private `data/`.

## Standing decisions

- Use default Luna/Sol routing. Escalate Luna `supports` results to Sol.
- Polaris is the only scanner input. Focus on SAST and SCA.
- Require `--profile-file`. There is no default lockfile.
- Keep open findings open without routine sign-off.

## Next, in order

1. Node-RED 5.0.8 untuned run (DoD 3). Needs an owner Polaris Bridge scan on `935b8d3e`.
2. Owner decision: the Codex read-only sandbox can read files (see PLAN.md, "Open after F3").
3. Delivery to a security team. The owner handles this.

The clean-machine setup test is deferred to Later (2026-10-07). DoD 1 stays open until it runs.

See [PLAN.md](PLAN.md) for each Definition of Done check.
