# Plan

Source: [FVA scope audit](https://claude.ai/code/artifact/cb497855-cb26-4915-bcfb-5d4b72b6b8ab)
(2026-10-05, audited at `4d8edd9`). Sections 8 and 9 are copied below; the audit has the
reasoning, the feature table and the full deletion list (section 6).

## Shortest path to done

Five items, in this order. Do the deletion first so the rest happens in a smaller codebase.

### Should remove/simplify

- [ ] **Delete the side quests in one PR.** The first four rows of section 6 (blind pilot,
  passive runtime, Polaris research tools, plan and log files), then rerun `fva score` on Juice
  Shop and confirm auto share, agreement and incorrect demotions don't move. Shrink CHECKPOINT
  to a STATUS file under 60 lines.

### Must fix

- [ ] **Decide the human question.** Either "no routine human review: open findings simply stay
  open" (then remove `import-review`) or "a reviewer signs off" (then update the project
  description). Write the answer in the README.
- [ ] **Make a second app possible from the README.** Require `--profile-file` (no Juice Shop
  default), drop the Juice Shop lockfile default, warn when finding paths don't exist in the
  source, and document the profile in ten lines. Default the client to what a new user can run.

### Must validate

- [ ] **Run one app the rules were never tuned on.** A real Node app with a Polaris scan, an
  empty model cache, no rule changes during the run. Hand-check 30 random auto-closed findings
  and all `likely` ones. Fix rules only for errors found, then stop.
- [ ] **Prove one output reaches a security team.** Import `fva sarif` output into Polaris and
  confirm the verdicts show. If that fails, `report.html` is the deliverable.

### Later (explicitly not now)

Active runtime probes, SAST-to-DAST linking, Polaris write-back, more advisory call sites, other
languages, a multi-app benchmark, Jev. The company GitHub move and the LiteLLM client gate real
customer data, so they come right after done, not before.

## Definition of Done

FVA is done when all six checks below pass on a clean machine. After that, only bug fixes; any
new feature needs a failing check to justify it.

1. **Setup.** From the README alone, `pip install -e .` plus one command runs the full pipeline
   on a new app in under 15 minutes. No Windows paths, no Juice Shop defaults, no private
   `data/` needed beyond the scan export.
2. **Regression.** On Juice Shop, `fva score` shows auto share of at least 80% and 0 incorrect
   demotions, on fresh model answers, not cache.
3. **Generalization.** On one Node app the rules were never tuned on, the tool auto-decides at
   least half the findings, and a hand check of 30 random auto-closed findings finds 0 real
   problems closed.
4. **Honest leftovers.** Every open finding in the report says what evidence is missing.
5. **Delivery.** One output (SARIF in Polaris, or `report.html`) is opened by someone other
   than you and acted on without explanation.
6. **Repeatable.** A second run on the same inputs gives the same verdicts and costs $0.
