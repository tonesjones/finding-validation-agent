# Plan

Source: [FVA scope audit](https://claude.ai/code/artifact/cb497855-cb26-4915-bcfb-5d4b72b6b8ab)
(2026-10-05, audited at `4d8edd9`). Sections 8 and 9 are copied below; the audit has the
reasoning, the feature table and the full deletion list (section 6).

## Shortest path to done

Five items, in this order. Do the deletion first so the rest happens in a smaller codebase.

### Should remove/simplify

- [x] **Delete the side quests in one PR.** PR #42 removed the first four rows of section 6. Juice Shop scores are unchanged. The checkpoint was also reduced to a STATUS file under 60 lines.
  - Acceptance criteria: PR #42 is merged, the scope-cut changes are absent, and STATUS.md is under 60 lines.

### Must fix

- [x] **Decide the human question.** Decision: no routine human review; open findings stay open; `import-review` is removed. Update the README to state this policy.
  - Acceptance criteria: README states the policy, and the `import-review` command is removed from the CLI and documentation.
- [ ] **Make a second app possible from the README.** Require `--profile-file` (no Juice Shop default), drop the Juice Shop lockfile default, warn when finding paths don't exist in the source, and document the profile in ten lines. The default client stays `codex` (owner decision 2026-10-05; may switch to `anthropic` later).
  - Acceptance criteria: README setup uses a profile on a non-Juice-Shop app, the CLI requires `--profile-file`, and missing source paths produce a warning.

### Must validate

- [ ] **Run one app the rules were never tuned on.** The app is Record Desk (`C:\TestCode\fva-eval-demo`, 1 SAST + 5 SCA findings). Hand-checking is done by GPT-6.1 Sol against redacted source, with Claude reviewing only disagreements (owner decision 2026-10-05). Six findings are fewer than the 30-sample check, so check all auto-closed findings.
  - Acceptance criteria: record the run with an empty model cache and no rule changes, then check every auto-closed finding and all `likely` findings; resolve only errors found.
- [ ] **Prove one output reaches a security team.** Import `fva sarif` output into Polaris and confirm the verdicts show. If that fails, `report.html` is the deliverable.
  - Acceptance criteria: capture evidence that a reviewer other than the author opened and acted on Polaris SARIF or `report.html`.

### Later (explicitly not now)

Active runtime probes, SAST-to-DAST linking, Polaris write-back, more advisory call sites, other languages, a multi-app benchmark, Jev. The company GitHub move and the LiteLLM client gate real customer data, so they come right after done, not before.

## Definition of Done

FVA is done when all six checks below pass on a clean machine. After that, only bug fixes; any new feature needs a failing check to justify it.

1. **Setup.** From the README alone, `pip install -e .` plus one command runs the full pipeline on a new app in under 15 minutes. No Windows paths, no Juice Shop defaults, no private `data/` needed beyond the scan export.
2. **Regression.** On Juice Shop, `fva score` shows auto share of at least 80% and 0 incorrect demotions, on fresh model answers, not cache.
3. **Generalization.** On one Node app the rules were never tuned on, the tool auto-decides at least half the findings, and a hand check of 30 random auto-closed findings finds 0 real problems closed.
4. **Honest leftovers.** Every open finding in the report says what evidence is missing.
5. **Delivery.** One output (SARIF in Polaris, or `report.html`) is opened by someone other than you and acted on without explanation.
6. **Repeatable.** A second run on the same inputs gives the same verdicts and costs $0.
