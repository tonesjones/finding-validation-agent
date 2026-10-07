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
2. Dev-only dependency rule (fix 1) and README profile guidance (fix 2). Planned below.
3. Third untuned app, Habitica. Blocked on its Polaris scan.

The clean-machine setup test is deferred to Later (2026-10-07, owner decision). DoD 1 stays open until it runs.

### Specific SAST gap sentences

On `20261005-js-fresh`, 52 of 73 open tickets get the generic SAST sentence.
37 are CWE-798 hard-coded credentials and 6 are CWE-79 XSS. The other 9 are single CWEs.
All 52 cite only neutral static, reachability and model evidence.
`fva/missing.py` is report-only, so this changes no prompt, cache or verdict.

- [x] **Add a CWE-keyed gap table to the SAST fallback in `fva/missing.py`.**
  - CWE-798 names the missing evidence: whether the value is a live secret used by shipped code,
    or a placeholder, test fixture or public value.
  - CWE-79 names the missing evidence: whether untrusted input reaches the sink without encoding or sanitizing.
  - Also map the common injection CWEs (89, 78, 22, 918, 601), code eval (94, 95), null dereference (476)
    and code quality (398). Keep the generic sentence as fallback.
  - Sentences use only the CWE id from finding metadata. No finding text, paths or code are echoed.
- [x] **Tests.** `tests/test_missing.py` covers each mapped CWE, a multi-CWE finding, an unmapped CWE and a missing CWE.
- [x] **Check on Juice Shop.** Passed 2026-10-07: generic sentences fell from 52 to 6, each a different CWE. Rerun `fva report` on `20261005-js-fresh` with no model calls.
  - Done when no CWE with 2 or more open tickets gets the generic sentence, and the generic count is 10 or fewer.
  - Ticket count, ranks and closed issues are unchanged. Full pytest passes on Linux and Windows CI.

### Larger real second app

This closes the DoD 3 caveat: Record Desk's 6 findings cannot support a 30-finding sample.

- [x] **Choose the app.** Uptime Kuma (`louislam/uptime-kuma`), pinned at `2a4d763` (2026-10-05). Chosen 2026-10-07.
  It is a real self-hosted app with 520 non-test source files, an npm v3 lockfile and 18 published advisories.
  The advisories mean it holds known true positives as well as noise. No FVA rule or doc names it.
  NodeGoat was rejected because it is deliberately vulnerable, so it would yield too few true closures to sample.
  Habitica is the fallback.
- [x] **Polaris scan (owner).** SAST and SCA on commit `2a4d763` exactly. 265 issues: 142 SAST, 123 SCA.
- [x] **Fresh-cache run `20261007-uk-fresh` (2026-10-07). Fails the 50% bar.**
  - Auto share 56/265 (21%). 223 model calls (71 Luna, 152 Sol, 48 escalations), $2.21 list price.
  - All 56 auto-closures are path rules: 51 test files, 5 infrastructure files. Models and dependency rules closed nothing.
  - 55 of the 56 hold. The doubtful one is a low-severity root-user finding in `extra/docker-latest-warning/Dockerfile.latest-warning`,
    which builds a published image. It closed because the profile left `infrastructure` out of `deployed_surfaces`.
    The README does not say a container-shipped app should include it.
  - SCA: all 122 open. 65 are dev-only dependencies, but Vite bundles ~24 of the dev deps (vue, dompurify, chart.js)
    into the shipped frontend, so dev-only must not mean "not shipped". Staying open was correct.
  - SAST: 86 open. 45 are "Bad Use Of Null-like Value" (CWE-476), 41 of them in `server/notification-providers`.
    10 model refutations were held as `MODEL_ONLY_REFUTATION`, as the rules require.
  - Any fix tuned on these results must be measured on a third untuned app, not on Uptime Kuma again.
- [ ] **Export and profile.** Export through the read-only Polaris MCP into `data/` (never committed).
  Write a profile file from the README profile section only. Note any README gap found on the way.
  - Profile written to `data/runs/uptime-kuma-2a4d763-profile/profile.json` with no app-specific path rules.
  - README gap: it names `deployed_surfaces` but not the allowed values. They are only in `fva/schemas.py`.
- [ ] **Fresh-cache run.** Run `assess`, `triage` and `report` with default Luna/Sol routing. Record calls and list-price cost.
- [ ] **Sample check.** Draw 30 auto-closed findings with a fixed seed. GPT-6.1 Sol checks each against redacted source.
  Claude reviews every disagreement against the pinned source.
- [ ] **Done when** auto share is at least 50% and 0 of the 30 sampled closures are real problems.
  Any fix needs a failing check first and then a rerun. Record results in STATUS.md, not the app's data.

### Dev-only dependency rule (fix 1)

On Uptime Kuma, 65 open SCA findings are dev-only in the lockfile. About 24 of them (vue, dompurify, chart.js)
are bundled into the shipped frontend, so a lockfile `dev` flag alone must never close a finding.
The Node import scan reads only `.js/.ts`-family files. It cannot see imports in Uptime Kuma's 182 `.vue` files
or SCSS `@import`s, so the rule must not rely on the import graph alone.

- [ ] **Rule.** A new skip disposition `dependency:dev_only_not_shipped` closes an SCA finding as `not_applicable`
  with a new appended reason code `DEV_DEPENDENCY_NOT_SHIPPED`, at medium confidence, only when all of these hold:
  - A lockfile is given. The scanned version is present, and every installed instance of the package is `dev`.
  - No non-test file references the package name as a module specifier or path (`'pkg'`, `"pkg/..."`, `~pkg`).
    This text scan covers every file type, `.vue`, `.scss`, `.html` and config files included.
    It skips `node_modules`, package manifests, lockfiles, and test, fixture and documentation surfaces.
  - No dev package referenced by a non-test file has the package in its lockfile dependency closure.
  - Medium confidence means high and critical closures stay open with `HIGH_IMPACT_CLOSURE`.
  - The new code stays out of `MODEL_CODES`, so prompts and the model cache are unchanged.
- [ ] **Tests.** A failing test first for each case.
  - Closes: dev package referenced nowhere, or only in test files, docs, `package.json` or the lockfile.
  - Stays open: a reference in a shipped `.js`, `.vue` or `.scss` file, or in a build config such as `vite.config.js`.
  - Stays open: a transitive dependency of a referenced dev package, a package with a non-dev installed instance,
    a run with no lockfile, and version drift (which keeps its existing rule).
- [ ] **Checks.** Juice Shop regression stays at DoD 2 (auto share at least 0.80, 0 incorrect demotions) on cached answers.
  Every new Juice Shop closure agrees with the ledger.
  On Uptime Kuma, Claude checks every new closure against the pinned source; 0 may be bundled or loaded at runtime.
  The 50% bar is not judged on Uptime Kuma, because the rule was tuned on it.

### README profile guidance (fix 2)

- [ ] **README.** The profile section lists the allowed `deployed_surfaces` values and says what each one means.
  It tells container-shipped apps to include `infrastructure`, because their Dockerfiles ship.
  It says which lockfile to pass: the npm v2 or v3 `package-lock.json` at the scanned commit, for the shipped app.
  It says the dev-only rule needs that lockfile. Written with the technical-writing skill.

### Third untuned app

- [ ] **Habitica (owner scan).** Polaris SAST and SCA on one pinned commit. Then a fresh-cache run, the 30-closure
  sample check, and the 50% bar from "Larger real second app". No rule changes may be tuned on it before the run.

### Later (explicitly not now)

The clean-machine setup test (DoD 1), active runtime probes, SAST-to-DAST linking, Polaris write-back, more advisory call sites,
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
