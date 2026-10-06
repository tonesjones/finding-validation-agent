# Plan

FVA closes Polaris SAST and SCA findings only when cited evidence proves they do not apply.
The rest stay open in a ranked report with missing evidence. DAST is parked.
Source: the [FVA scope audit](https://claude.ai/code/artifact/cb497855-cb26-4915-bcfb-5d4b72b6b8ab) (2026-10-05).

## Shortest path to done

### Should remove/simplify

- [x] **Delete the side quests.** Done in PR #42 and PR #43.
  - The deleted tools are absent. STATUS.md stays under 60 lines.

### Must fix

- [x] **Decide the human question.** Done in PR #43.
  - No routine human review. Open findings stay open. `import-review` is removed.
- [ ] **Make a second app possible from the README.** Code done in PR #43.
  - `--profile-file` is required. An example profile and README profile section exist.
  - There is no Juice Shop lockfile default. Missing SAST paths produce a warning.
  - Still open under DoD 1 is the clean-machine test from the README alone.
  - The default client stays `codex`.

### Must validate

- [x] **Run one app the rules were never tuned on.** Done on Record Desk with a fresh cache.
  - The run had 6 findings, with 1 SAST and 5 SCA. Before the fix, 4 of 6 were auto-decided.
  - GPT-6.1 Sol checked the 4 auto verdicts against redacted source and agreed on 3. Both auto-closures held.
  - The disagreement was an over-flag on lodash CVE-2026-4800 involving template imports.
  - PR #44 fixed it with an option precondition. After the fix, 3 of 6 are auto-decided.
  - The imports closure stays open with `HIGH_IMPACT_CLOSURE`.
  - Six findings are thin evidence. A larger real app is the stronger test.
- [ ] **Prove one output reaches a security team.** Open. The owner handles delivery.
  - Import `fva sarif` output into Polaris and check the verdicts. If that fails, use `report.html`.
  - Capture evidence that someone other than the author opened and acted on the output.

### Next, in order

1. Delivery to a security team. The owner handles this.
2. A larger real second app.
3. A clean-machine setup test from the README alone.
4. Specific SAST gap sentences.

### Later (explicitly not now)

Active runtime probes, SAST-to-DAST linking, Polaris write-back, more advisory call sites,
other languages, a multi-app benchmark and Jev.
The company GitHub move and LiteLLM client gate real customer data.
They come right after done, not before.

## Definition of Done

FVA is done when all six checks below pass. Setup must pass on a clean machine.
After that, only bug fixes. Any new feature needs a failing check to justify it.

1. **Setup.** From the README alone, `pip install -e .` plus one command runs the full pipeline on a new app in under 15 minutes.
   No Windows paths or Juice Shop defaults. No private `data/` is needed beyond the scan export.
   - Open. The clean-machine test remains.
2. **Regression.** On Juice Shop, `fva score` shows auto share of at least 80% and 0 incorrect demotions on fresh model answers.
   - Passed 2026-10-05 on `20261005-js-fresh`. Auto share 0.841, auto agreement 0.996, 0 incorrect demotions, 101 calls, $0.86.
3. **Generalization.** On a Node app the rules were never tuned on, auto-decide at least half the findings and check 30 random auto-closed findings against source with 0 real problems closed.
   - Passed on Record Desk with the caveat above. All auto-closures held, but 6 findings cannot support a 30-finding sample.
4. **Honest leftovers.** Every open finding in the report says what evidence is missing.
   - Passed in PR #45. Every open ticket has `missing_evidence`. Of 73 Juice Shop tickets, 50 get a generic SAST sentence.
5. **Delivery.** Someone other than you opens SARIF in Polaris or `report.html` and acts on it without explanation.
   - Open. The owner handles delivery.
6. **Repeatable.** A second run on the same inputs gives the same verdicts and costs $0.
   - Passed. The cached rerun cost $0 with identical verdicts on all 573 findings.

The Juice Shop answer key came from an LLM-driven experiment and has not been independently adjudicated.
