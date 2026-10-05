# Checkpoint

Last updated: 2026-10-05. Update this file when status changes.

## Integration review and current findings (2026-10-05)

- PR #38 (DAST plan) is merged. PR #39 combines the real-envelope implementation
  and measured results with that plan; this checkpoint accompanies its reviewed
  merge. The original Codex prompt is retained as historical context, not repeat
  scan authorization. Shared plan text preserves the owner's local API scan scope.
- Review covered both changed source files, tests, sanitized fixtures and docs,
  including the redaction and confirmation boundaries. Scanner counts use the
  same finding-type values as scanner-mix keys. No code defect was found in this
  bounded review; broken document encoding and stale assumed-envelope text were
  corrected. Combined local validation: 658 passed, 5 skipped. Linux/Windows CI
  was green at both reviewed heads and is checked again on the combined head
  before merge. No new scan or probe ran during review.
- Current grouped report: 504 issues, 78 open and 426 closed. Open issues comprise
  13 `likely` and 65 `needs_review`; closed issues comprise 411 `not_applicable`
  and 15 `valid_non_security`. These are grouped issues, not the 585 scanner rows.
- DAST supplied two medium, seven low and two informational findings: server
  error; sensitive form over HTTP; stack trace; deprecated or missing security
  and cache headers; internal IP disclosure; scanner settings and crawl reports.
  The last two are informational metadata, not demonstrated vulnerabilities.
  Transport findings describe the local HTTP deployment, not a hosted production
  environment. All 11 remain open; no static finding gained confirmation or closure.
- Entitlement and real-envelope integration are unblocked. The remaining evidence
  gap is active-attack/authenticated coverage and precise route/parameter linkage,
  not adapter readiness. This scan disabled active attacks and supplied no dedicated
  parameter fields. Plan a bounded local follow-up with positive/negative controls
  and explicit authorization before scanning or retrieving further runtime evidence.
  Do not lower link thresholds to manufacture confirmations or treat no-hit as safe.

## DAST FVA complete (2026-10-05)

- Work branch `codex/dast-fva` starts from `origin/main` at `18fc93b`.
  The plan was recovered from `claude/dast-fva-plan`; D0-D6 acceptance checks passed.
- The owner explicitly authorized project creation and scan launches through the
  API for FVA. SAST, SCA and DAST completed against local Juice Shop source commit
  `15b4641`. This authorization was limited to those scan prerequisites; the
  read-only MCP allowlist is unchanged. Credential values were kept out of outputs.
- DAST used a Linux Secure Tunnel and a private Docker target, with active attacks
  disabled and no host port exposed. Runtime source verification: 357 files,
  zero mismatches or missing files. Optional SBOM packaging was skipped; no app
  source was changed. Both temporary running containers were stopped after scans.
  No hosted target requests ran. This scan does not measure active-attack coverage.
- D0/D1: 518 SAST, 56 SCA and 11 DAST issues exported; all DAST context tool types
  verified. The DAST type sidecar has 11 entries. The census and schema inventory
  remain under ignored `data/`; the optional dashboard inventory has a required-ID
  error, while issue list/detail schemas and exports succeeded. Field names only
  are documented in `docs/operations.md`.
- D2/D3: all 11 real DAST IDs load byte-identically; nine endpoints have methods,
  two retain explicit missing-method metadata. No parameter fields were inferred.
  Structured evidence is referenced, not promoted to runtime proof. Type text now
  redacts interpolated target hosts and secrets. No new reason codes were needed.
  Sanitized real-envelope fixtures cover all issues and the text-redaction defect.
- D4: `data/runs/20261005-fva-dast` uses routed assessment, four workers and
  `dast-evidence` mode: 585 findings, 87 clusters, zero errors. All 87 clusters
  reused cached assessments: 51 Luna attempts and 46 Sol attempts, including six
  Luna `supports` and four low-confidence escalations. Cached metadata identifies
  the models; no fresh model calls ran. Current assessment cost is $0.00000;
  recorded historical priced cost is $0.16134 (incomplete historical coverage,
  not the total cost of creating the cache or a subscription savings estimate).
- D5: SAST-to-DAST links: high 0, medium 0, low 0. Precision is undefined for
  every tier because there are no links to review. All 11 DAST rows stay
  `needs_review`; zero findings are `confirmed`. The 464 other links are SCA to
  SAST. DAST added observations but supplied no linked static confirmation or closure.
- D6: score, report and SARIF completed, including 11 results in `dast.sarif`.
  Auto share 83.8%, auto agreement 99.4%, incorrect demotions 0 (auto 0).
  Compared with `20261004-js-merged`: auto share -1.0 percentage point,
  auto agreement unchanged, incorrect demotions unchanged at zero, overall
  agreement 86.9% versus 86.5% (+0.4 point). Label coverage is 564/585 versus
  baseline 570/573; all 11 DAST rows and ten SCA rows lack key labels. These
  differing populations prevent attributing the agreement change to DAST.
  Within the new run, static rows alone have 490/574 auto (85.37%); adding the
  11 review-only DAST rows lowers auto share to 490/585 (83.76%), by 1.61 points.
- Validation: Windows 658 passed, 5 skipped; Linux 657 passed, 6 skipped.
  Private exports, receipts, profiles, census, prompt audit and link review remain
  under ignored `data/`. The local prompt audit found zero credential, tenant or
  service-host matches in 87 redacted prompts. No files under `data/` are tracked.

## Current state

- PR #9 is merged. Blind discovery and frozen evaluation tooling are implemented.
- A 12-case paired assessment completed with all model identities verified, clean
  call audits, exact case-ID coverage and no processing failures. The score measures
  agreement with prewritten labels, not independently verified security accuracy.
- A Tony label receipt matches the paired run's frozen case set. The checked-in local
  readiness report predates that receipt; use the new aggregate-only eval status command
  to refresh status without displaying private labels or per-response content.
- Targeted validation observations were collected separately. They remain local;
  source identity, deployment details, results, authorization and artifact paths
  are recorded only in ignored `data/LOCAL-NOTES.md`.
- PR #10 is squash-merged into main as `966858c`.
  Automatic promotion of hand-built runtime and advisory-precondition records
  has been removed because those records have no verified collector receipt.
  Those records stay `needs_review`; prototype SCA closures are withdrawn.
- Suggestions bind runtime evidence to the run's authoritative deployment profile.
  Missing or mismatched profiles cannot confirm a finding. Runtime confirmation
  invariants require a neutral control linked to the supporting probe.
- Frozen evaluation artifacts remain unchanged. Historical prototype decision
  outputs are superseded, not current automatic triage results.
- A supported localhost GET collector/importer is implemented on
  `codex/runtime-collector`. It requires one approval for the exact plan, checks
  source/run binding, retains paired raw responses and recomputes evidence during
  import and worksheet generation. Only its approved SAST code-execution marker
  oracle can produce automatic runtime confirmation. Hand-built records remain open.
- PR #12 is squash-merged as `7efe961`. It adds exact npm lodash advisory ranges
  for five pilot advisories.
  Unknown IDs and malformed versions remain unresolved, and only a known out-of-range
  installed version can produce not-applicable; affected versions still require evidence.
- PR #11 review repairs require an interactive exact-plan approval, reject common
  encoded marker reflections and post-dated approvals, and surface receipt
  verification warnings. One collection per derived run is explicitly enforced.
- The collector has been exercised against a synthetic local server. Real pilot
  validation with this collector has not run. Hosted probing remains unimplemented;
  the bounded npm lodash advisory rules are implemented.
- Review validation: 340 tests passed, 10 skipped, including approval/allowlist gates,
  paired live collection, import, receipt-byte integrity and response deadlines.

## Next

- 2026-10-04: Building passive runtime evidence per `docs/plans/passive-evidence-demo.md`
  (no attack traffic, never `confirmed`). Step 0 done: on `20261003-js-assess-v2`, score
  gives 0.798 agreement, 0 incorrect demotions, 0.756 queue reduction. Whatif review
  queue is 123 now, 106 conservative and 85 optimistic (ceilings from the answer key).
  L1 (evidence contract) is merged as PR #15. S1 (Polaris triage fields) is PR #16. The saved
  export's `list_issues` triage properties are `status`, `is-dismissed` and `dismissal-reason`.
  Every one of the 573 issues is `not-dismissed` with reason `unset`, and set-by, set-at and
  history are absent. There are no labels to harvest, so S3 is skipped for this tenant.
  L2 (loaded-package collector) and S2 (coverage importer) are merged as PR #17. L3 (verdict rules) is
  merged as PR #18. L4 ran Juice Shop's server and API tests on Node 24.14 with both collectors, against
  `20261003-js-assess-v2`. The result is `20261004-js-l4-passive`. No verdict changed: 0 new closures,
  0 incorrect demotions, agreement 0.798, review queue 123 (the whatif ceiling was 106). 13 `likely` SAST
  findings now cite `EXECUTED_UNDER_TEST`. These numbers predate the T1-T8 merge below.
- PR #13 (paired status) is merged. Its aggregate command verified the existing
  sealed 12-case run with matching receipt, clean audits, exact case coverage and no
  processing failures.
- The source-identity app PR and advisory-range PR are merged. Prepare an exact
  collector plan for operator review before running the real pilot.
- 2026-10-04: T1-T8 (exception-routed triage, lodash call sites, assess-v2, ranked report and tickets,
  quality-checker closures) and the T6 oracle code were written 2026-10-03 on `claude/triage-exceptions`,
  never pushed, and are now merged into main through `claude/integrate-triage-exceptions`. Tasks and results
  are in `PLAN.md`. The model's allowed codes leave out the passive-observation codes, so the assess-v2 prompt and
  its model cache are unchanged. A full assess on merged main (`20261004-js-merged`) came entirely from cache.
  The result: 84.8% routed automatically with 99.4% agreement, needs_review 84, overall agreement 0.865,
  0 incorrect demotions. `fva report` gives 73 open and 426 closed issues. The L4 passive receipts, rebuilt for
  that run (`20261004-js-merged-passive`), again change no verdict, and the whatif ceiling is 67.
  L5: the pitch is `docs/demo-pitch.md`. S4: `fva report` also writes a static `report.html`. The demo plan
  is complete. CI is green on Linux and Windows, there are 0 incorrect demotions, measured counts replace the
  whatif estimate, and every branch merged through a PR. Next, as a new plan: the paused T6 live run below, the
  pilot collector plan, and DAST once the entitlement arrives.
- 2026-10-04: the new plan is `docs/plans/runtime-pilot.md`. Owner decisions: CVE-2021-23337 gets no probe
  and stays `likely` (a fix ticket), the demo run is not scored (no answer key), and the pilot collector plan
  is the table in that file. The only collection planned is the banner pair below.
- 2026-10-04: T6 live run done on the record-desk demo (local paths, hashes and the port are in
  `data/LOCAL-NOTES.md`). The scan is from `9ac5160`; the app ran from a clone at the source-identity commit
  `0f17d90`. The app's `X-FVA-Source-SHA256` header matched the run's source hash, so no hash fix was needed.
  The owner approved a one-pair `header_disclosure` plan (`GET /` for `X-Powered-By: Express`, `GET /message`
  as the control) with `runtime approve`. The collector sent 2 requests, both 200 and source-bound. Import
  confirmed the CWE-201 banner as `RUNTIME_CONFIRMED`, routed auto, citing the probe and its control. The
  other five findings kept their verdicts. The derived run decides 4 of 6 automatically: 1 confirmed,
  1 likely (CVE-2021-23337, a fix ticket), 2 not_applicable. 2 stay open: CVE-2026-4800 (conflicting
  evidence) and CVE-2020-28500 (ReDoS, no safe probe). The banner confirmation holds for `0f17d90`; the
  scan's `app.js:4` is a blank line there and the `express()` call is on line 5. The report and tickets
  contain no raw response bytes. The demo run was not scored (no answer key).
- 2026-10-04: new plan `docs/plans/unblocked-backlog.md` (credential default, cost accounting, malformed-input
  audit, API-client plan). Credential default measured on Juice Shop, all from cache: `ask` decides 5 of the 40
  assessed credential findings automatically (`routes/login.ts:59-64`, `likely`, all agree with the key) and
  `skip` decides none. Overall auto share 84.8% vs 83.9%, auto agreement 99.4% in both, 0 incorrect demotions in
  both. Decided 2026-10-04 by the owner: `ask` stays the default; `skip` stays opt-in. API client: recommend not building it (saves
  about $0.12 per fresh run at list prices and moves spend off the subscription).
- 2026-10-04: cost accounting (backlog item 8, `docs/plans/unblocked-backlog.md` item 2). Codex runs with
  `--json`; each fresh call records input, cached-input and output tokens in its cache meta, the model comes from
  the `model:` header or Codex's session file, and `summary.json` has a `cost` block from `fva/reasoning/pricing.py`
  (`--prices` overrides). Cache keys are unchanged: a full Juice Shop assess on the branch came entirely from cache
  with identical triage on all 573 findings. Answers cached before this change have no usage, so they cost $0 in a
  run and add nothing to `usd_when_first_made`.
- 2026-10-04: real smoke calls, one per model, on the same first cluster with an empty cache dir. With `--json`, Codex
  still writes the last-message file and prints no `model:` header; the session file named the model correctly for
  both. Luna: 25,239 input, 0 cached, 130 output, $0.0026. Sol: 23,318 input, 0 cached, 223 output (102 reasoning),
  $0.0489. Codex's prompt cache was cold, so these cost about 4x the warm-cache estimate (Sol 1.24 cents); a full
  run's real cache hit rate is still unmeasured. Sol's visible answer (223 - 102 = 121) is close to Luna's 130, which
  supports the assumption that `output_tokens` includes reasoning. Usage also has `cache_write_input_tokens` (0
  here), which the price table ignores.
- 2026-10-04: malformed-input audit (`docs/plans/unblocked-backlog.md` item 3). Every adapter loader (SARIF,
  generic mapping, Polaris flat, MCP and DAST, PoC ledger) raises `ValueError` naming the file and record for
  truncated, invalid or wrongly shaped input, before returning any findings, and leaves the input bytes unchanged.
  Empty JSONL or CSV files still mean zero findings. The real Juice Shop export (573) and PoC ledger (570) load as before.
- 2026-10-04: plan `docs/plans/remaining-unblocked.md`. ROADMAP synced with the code. `summary.json` has a
  `versions` block, and the `tokens` stat is rebuilt from usage under `--json`. `fva sarif` (PR #33) and `fva preview`
  (PR #34, dry run, label map ASSUMED). A fresh full Juice Shop run (`20261004-js-fresh-cost`, separate cache):
  97 calls, $0.825 at list prices, Codex prompt cache 68.2% hit (Luna 64%, Sol 74%; Sol 1.91 cents per call). Same auto
  share (84.8%) as the cached baseline, auto agreement 98.8% vs 99.4%, 0 incorrect demotions, 4 over-flags (baseline 1). 8 of the
  9 changed rows came from Luna answers. Two are credential `likely` rows the key calls inactive, so on fresh answers `ask`
  gives 3 correct and 2 wrong credential decisions.
- 2026-10-04: owner decision: a Luna `supports` escalates once to Sol, so no `likely` rests on Luna alone. On the
  baseline's cached answers (`20261004-js-sol-supports`, 6 fresh Sol calls, $0.16) Sol backed 3 of 6 and left 3
  `routes/login.ts` credentials (key: confirmed) open. Auto share 84.8% to 84.3%, auto agreement 99.4% in both,
  0 incorrect demotions. The fresh-run over-flags it targets are not measured yet (7 Sol calls).
- Routine triage does not require grading model responses; open findings stay open as
  "open, not auto-verified".
- 2026-10-05: DAST entitlement resolved. A new Polaris app "FVA" has SAST, SCA and DAST. The DAST freeze is
  lifted for `docs/plans/dast-fva-app.md`; Codex runs it from `docs/plans/dast-fva-codex-prompt.md`.

## Historical development log

The detailed dated pilot/authoring history and local identities were moved to
`data/LOCAL-NOTES.md`. The reference implementation notes below are historical;
they are not instructions to rerun or replace the frozen pilot.

## Built (package `fva`, Python >= 3.10, tests: `python -m pytest`)

| Area | Module | Status |
|---|---|---|
| Canonical schemas | `fva/schemas.py` | IngestionRun, Finding, EvidenceRecord (many findings per record), DeploymentProfile, Verdict (append-only, `supersedes`) |
| Reason codes | `fva/reason_codes.py` | Vocabulary v1: 35 codes (4 appended 2026-10-01: 2 `likely`, 2 reviewer; 2 appended 2026-10-04: `PACKAGE_NOT_LOADED`, `EXECUTED_UNDER_TEST`; 7 written 2026-10-03 and merged 2026-10-04: 5 triage exceptions, 2 call sites); 16 map 1:1 from the PoC |
| Verdict invariants | `fva/invariants.py` | confirmed needs `supports`, not_applicable needs `refutes`, conflict forces needs_review; `likely` needs `supports` plus rule-derived static evidence; `PACKAGE_NOT_LOADED` needs a not-loaded observation beyond startup and no shipped import; `EXECUTED_UNDER_TEST` needs an executed line and a static or model `supports` |
| Scanner mix | `fva/pipeline.py`, `fva/runtime_mode.py` | any mix; no DAST -> runtime mode `none`; SCA↔SAST and SAST↔DAST links + groups wired in; `findings.jsonl` indexes every original finding |
| Automatic scoring | `fva/export/score.py` | `python -m fva score <run>` vs PoC ledger: agreement, incorrect demotions, unresolved, queue reduction, by tier/scanner -> `score.md/json`, `score_rows.csv` |
| Passive observations | `fva/observations.py` | receipt format `fva.runtime_observation/1` -> `runtime_observation` evidence bound to run profile, source and findings; neutral, or `refutes` for a package not loaded; `import_receipt` writes a new run after the collector rebuilds the receipt from raw output |
| Passive collectors | `fva/loaded_packages.py` + `fva/node/loaded_modules.cjs`, `fva/coverage.py` | Node preload records loaded module paths (append as loaded, ESM via `registerHooks`); "not loaded" only with complete records; V8 or c8 coverage -> `line_executed`; verdict rules in `docs/operations.md` |
| Triage worksheet | `fva/export/` | `worksheet.csv/.html` per Polaris issue id; suggestions pass invariants; `import-review` -> `human_review` evidence, superseding verdicts, agreement score |
| Suggested verdicts | `fva/verdicts.py` | rules over a run's evidence; every closure, rule closures included, must pass `check_verdict`; observations count only after the worksheet re-verifies their receipts |
| Rule evidence | `fva/surface.py` (`to_evidence`), `fva/pipeline.py` | skipped findings keep `deployment_boundary` / `dependency_resolution` / reachability records; never sent to a model |
| Polaris data tools | `fva/polaris_mcp.py` (`inventory`), `fva/analysis/` | read-only MCP survey; sanitized field census with adapter-dropped keys; correlation value (coverage, fan-out, coherence, lift) of candidate join keys vs the PoC ledger |
| Parallel assess | `fva/pipeline.py`, `fva/reasoning/model.py` | `--workers N`, results consumed in cluster order; per-thread CLI model/token fields |
| Severity tables | `fva/severity.py` | SARIF level, CVSS bands, vendor strings; unknown strings fail loudly |
| Raw provenance | `fva/provenance.py` | content-addressed refs `raw:sha256:<hex>#<pointer>` |
| Redaction | `fva/redact.py` | tokens, JWTs, cookies, cloud keys, secret assignments; all literals for credential CWEs |
| Language packs | `fva/langpacks/` | interface + Node pack (path rules, package.json, lockfile / node_modules inventory) |
| Deployment boundary | `fva/surface.py` | reproduces PoC surface for 569/570 rows (Dockerfile disagreement is deliberate) |
| Adapters | `fva/adapters/` | SARIF 2.1.0; generic field mapping (CSV/JSON/JSONL); Polaris (flat record shape); PoC ledger importer |
| Source pinning | `fva/correlation/source_pin.py` | git or archive import; CRLF-neutral content hash; tracked files only; never writes the git index |
| File/line correlation | `fva/correlation/locate.py` | 524/524 PoC SAST findings located exactly; redacted snippets |
| Dependency reconciliation | `fva/correlation/dependency.py` | reproduces all 18 PoC version-drift rows |
| Polaris MCP client | `fva/polaris_mcp.py` | read-only allowlist; `sample`, `probe`, `export` commands; token from `POLARIS_ACCESS_TOKEN` or `data/.polaris-token` |
| Static reachability | `fva/correlation/reachability.py` | import graph from profile entrypoints (SAST); package import sites in shipped vs test code (SCA); never `supports` |
| Model assessment | `fva/reasoning/` | swappable clients (Anthropic, OpenAI-compatible local, scripted); redacted prompts; citations verified against pinned source; cached by prompt/model/source hash |
| Batch pipeline + CLI | `fva/pipeline.py`, `python -m fva assess` | boundary -> locate -> dependency -> reachability -> model, one model call per cluster (same sink/advisory); `--dry-run` writes prompts only |
| Model routing | `fva/reasoning/routing.py` | Luna/Sol per cluster, one escalation, `--astra`, `--no-route`; tier and reported model in `tool_versions` |
| Subscription CLI clients | `fva/reasoning/model.py` | `CodexCliClient` (`codex exec`), `ClaudeCodeClient` (`claude -p`); run in an empty temp dir; commands overridable via `FVA_CODEX_CMD` / `FVA_CLAUDE_CMD` |
| Polaris raw-issue adapter | `fva/adapters/polaris.py` (`load_mcp`) | reads get_issue / list_issues responses; package identity from `component-origin-external-id`; drops internal links/tenant id |
| DAST adapter | `fva/adapters/polaris.py` (`load_dast`) | DAST issues -> Finding with `EndpointRef` (app-relative path only, host dropped); redacted 500-char snippets and type text; structured FVA envelope verified on 2026-10-05; missing methods/parameters stay explicit |
| Runtime mode | `fva/runtime_mode.py` | `none` / `dast-evidence` (default) / `live-localhost` (http(s) localhost targets only) |
| SAST↔DAST links | `fva/correlation/runtime_link.py` | Express route table + CWE + parameter near sink; high/medium/low |
| SCA↔SAST links | `fva/correlation/package_link.py` | shipped import in the SAST file + CWE; test-only imports never link |
| Grouping | `fva/correlation/grouping.py` | connected components; every finding kept; SAST primary |
| DAST evidence | `fva/correlation/dast_evidence.py` | only high-confidence links `support`; no DAST hit = no evidence; reason code `DAST_OBSERVED` |

## Decisions

- 2026-10-04 (L4): On Juice Shop 20.2.0 the passive signals do not tell true findings from false ones, which
  backs keeping them out of `supports`. All 6 packages behind the 29 open SCA findings loaded under the tests,
  and every one has a shipped import, so `PACKAGE_NOT_LOADED` cannot fire. The ledger calls those findings 7
  confirmed, 9 not_applicable and 12 needs_review (1 is not in the key). Of the 44 open SAST findings whose line
  ran, the ledger has 10 confirmed, 9 not_applicable and 25 valid_non_security. On merged main the quality rule
  closes most of the valid_non_security ones. 24 stay open: 10, 9 and 5. 7 of the 29 SCA findings
  are closed by `ADVISORY_PRECONDITION_ABSENT` even though their package loaded. The whatif ceiling assumed the
  answer key picks which signal settles each finding; the real signals carry no such information. The 5 lines
  that never ran are all Polaris dead-code findings that the ledger calls valid_non_security. The T8 quality-checker
  rule already closes them as `QUALITY_NOT_SECURITY` by checker id, so no observation rule is needed.
- 2026-10-04: Passive `runtime_observation` evidence does not count toward `likely` and never confirms. It is in
  neither `CONFIRMING_TYPES` nor `RULE_TYPES`, and the schema allows only `neutral`, or `refutes` for a package that
  was not loaded. A coverage hit shows that code ran, not that it is vulnerable, so a `likely` still needs a cited
  static or model `supports` plus rule evidence. Observations only pick the reason code (`EXECUTED_UNDER_TEST`,
  `VULNERABLE_VERSION_IMPORTED`). Invariants are unchanged. L3 must add two code checks to `fva/invariants.py`.
  First, `PACKAGE_NOT_LOADED` needs a no-shipped-import reachability record. Second, it needs an exercise broader
  than "startup only", because lazy `require` calls can be missed. Done in L3: `startup`, `startup only` and
  `npm start` are too narrow. A loaded package with no `supports` stays where it was, so the plan's "loaded ->
  likely" holds only when a cited argument already exists.
- 2026-10-02: The PoC tenant has no DAST. Freeze the DAST stack (no extensions) until a real DAST export exists;
  measure what Polaris returns for SAST/SCA (inventory, census) and the decision value of candidate links
  (correlation-value) before building more linking.
- 2026-10-02: A rule closure must cite a recorded rule result like any other verdict; no evidence, no closure.
- 2026-10-01: Not every customer has DAST (non-web apps: SAST+SCA only). Added verdict `likely` (static evidence,
  never confirmed); a reviewer's sign-off in the worksheet confirms it.
- 2026-10-01: Polaris MCP is read-only, so results cannot go back through it. Now: triage worksheet (mainly the
  record for testing fva). Later (v0.8): separate, approval-gated Polaris REST writer with its own token.
  Triage status labels in `fva/export/polaris_triage_map.py` are ASSUMED until checked against Polaris docs.

- SAST engine is Polaris only (no Semgrep/CodeQL).
- The model never produces `confirmed` on its own; it emits cited evidence, rules decide verdicts.
- Model step must be swappable for a local model.
- Confidence is `high | medium | low`.
- `confirmed` requires `supports` evidence from runtime probes, negative controls, human review or an imported
  assessment. Static reachability and model output can never confirm (enforced in `fva/invariants.py`).
- Real scanner data, lockfiles, tokens and PoC outputs live in `data/` (git-ignored). Only sanitized fixtures are committed.

## Findings about Polaris MCP (from live samples, 2026-09-27)

- `get_issue` returns no SAST data-flow trace; `coverity-events` is only a hash reference.
- SCA returns a reachability label only (`REACHABLE`/`UNDETERMINED`), plus the real package id
  (`component-origin-external-id`, e.g. `jsonwebtoken/0.4.0`, namespace `npmjs`), fix version, CVSS and upgrade guidance.
- Server exposes 10 tools; `list_component_versions` is undocumented in the product docs.
- Reachability evidence is not exposed: only the label and `reachabilityEvidenceCount`. Issue-level and
  component-level labels can disagree (multer: REACHABLE vs UNDETERMINED). Treat the label as a scanner hint.
- `includeComponentLocations` returns only the manifest declaration line (e.g. `package.json:135`); match
  type `FILE_DEPENDENCY_DIRECT` confirms Polaris scanned declared ranges, not the resolved install.
- Live export (2026-09-27) vs PoC ledger: all 570 ids present with identical core fields; 3 new SCA issues;
  4 reachability labels changed. Polaris package identity reproduces every hand-written name alias.
- Raw responses contain internal service URLs and the tenant id in `context._links`; never commit raw responses.
- `list_issues` returns no issue-type info; `export` fetches it once per `weaknessId` into `types.json`.
- Cloud workspace can now reach the Polaris API host (allowlisted 2026-09-27).

## Operating model and model routing (decided 2026-09-27, built in session 2: `fva/reasoning/routing.py`)

Built as specified below, with these implementation decisions:
- Routing is on for `--client codex` unless `--model` or `--no-route` (Sol for every cluster) is given; `--astra <source_finding_id>`
  (repeatable) sends that cluster to Astra. A cluster goes to Sol if any member would.
- Added to the Sol list from the Juice Shop dry run: CWE-345 (`jwt_untrusted_decode`), CWE-613
  (`jwt_revoke_missing`), CWE-676 (`unsafe_eval`), CWE-95. High severity with an unlisted CWE also goes to Sol;
  listed Luna CWEs stay on Luna at any severity below critical (escalation covers a Luna `refutes`).
- Codex CLI errors are not escalated (infrastructure, not model mismatch); they are recorded as errors.
- Only the final answer goes to `evidence.jsonl`; Luna's escalated attempt is kept in `assessments.jsonl` `attempts`.
- `agent_model` comes from Codex's `model:` header and is cached in `<key>.meta.json` beside the answer.
- Juice Shop first pass: 131 clusters -> 89 Luna, 42 Sol (`--dry-run` writes `routing.jsonl`).


Roles: Claude (Opus) is VP of engineering: sets policy, reviews combined runs, spot-checks claims, owns the
final review. Codex runs the assessments on the user's subscription: **GPT-6 Luna** (junior, low cost, bulk
first pass) and **GPT-6 Sol** (senior, judgment and security-sensitive calls). Routing mirrors the user's
Codex `tokenomics` skill (copy in `data/codex-tokenomics-skill.md`, not committed):

- `codex exec` fixes the model at launch, so routing happens in fva per model call (`-m <model>`), not inside
  the skill. Tell Codex not to delegate or spawn children inside an assessment call.
- **Luna first** (clear, bounded, low ambiguity): dead code / no-effect / quality CWEs (e.g. 398, 561, 563),
  hard-coded credential vs label checks, other low/medium non-injection findings.
- **Sol first** (security-sensitive or judgment-bearing): injection and code execution (e.g. CWE-78, 79, 89, 94,
  943), SSRF (918), authn/authz and JWT (284, 285, 287, 347, 639, 862, 863), crypto (320, 326, 327),
  SCA advisory-precondition questions, and any critical-severity finding.
- **Escalate Luna -> Sol once** when Luna is mismatched: citations rejected, unparseable output, conflicting
  claims, low self-reported confidence, Luna `refutes` a high/critical finding, or Luna `supports` (owner,
  2026-10-04: no `likely` rests on Luna alone). No further retries.
- **Astra** is never automatic; only on an explicit flag for a specific hard cluster.
- Record who did the work: `tool_versions.agent_model` from the model Codex reports running (its header
  line `model: ...`), not just the requested one; plus `routing_tier` and `routing_reason`. Cache keys already
  include the model, so tiers never mix.
- Model names configurable: `FVA_MODEL_JUNIOR` (default `gpt-6-luna`), `FVA_MODEL_SENIOR` (default `gpt-6-sol`).
- Review metrics for the VP review: per-tier agreement with the PoC, escalation rate and reasons, rejected
  citations per tier, calls and time per tier.

## Juice Shop reachability results (2026-09-27)

- Import graph from `server.ts`, `app.ts`, `frontend/src/main.ts`: 640 code files, 285 reachable.
- All 85 production SAST code findings sit in the entrypoint graph; the other 30 are non-code (e.g. `data/static/users.yml`).
- All 12 vulnerable SCA packages are imported by reachable code, so import-level reachability does not separate
  Juice Shop's SCA findings. The PoC separated them by version drift (built) and advisory preconditions (model step).

## First routed run review (2026-09-27, `data/runs/20260927-full-routed/`)

Run: 573 findings -> 131 clusters (130 in the PoC ledger, 1 new SCA), 0 errors, 23 min wall.
Luna 89 calls / 660 s (7.4 s avg), Sol 82 calls / 725 s (8.8 s avg). Codex header confirmed the model on every call.

- **Safety holds.** 1 model `refutes` on a PoC-confirmed cluster: `jwt_revoke_missing` at `lib/insecurity.ts:53`.
  Sol's claim is accurate for the flagged `denyAll` line; the PoC confirmed the weakness via `isAuthorized`.
  Runtime evidence would conflict and force needs_review, so the invariants cover it. Invented citations:
  Luna 1, Sol 0 (the other 9 Luna rejections were unparseable output).
- **Raw agreement is low (Luna 7/49, Sol 28/81) but mostly a vocabulary mismatch, not wrong answers:**
  - Quality findings (42): models almost never say `non_security`. They say `supports` (the quality issue exists)
    or `refutes` (18). Spot check: `lib/utils.ts:247` `void Promise.resolve(fn(...)).catch(next)`, where Luna's
    refutation is correct; Polaris `no_effect` is wrong there, and the PoC label was generous.
  - Credentials (40): 30 end `neutral`. Correct behaviour: credential CWEs redact all literals, and "active"
    was proven at runtime in the PoC. Static and model evidence cannot decide these.
  - `true_positive_runtime_exploited` SCA (5) -> neutral: expected, runtime-only.
- **Real gaps:**
  - SCA advisory preconditions: 0/6 `component_present_but_cve_precondition_absent` refuted (all neutral).
    This was the model step's intended job; the prompt lacks advisory detail and config/usage context.
  - Sink restatement cancels refutations: `routes/captcha.ts:22` `unsafe_eval`. Sol cited that the eval input
    is built from fixed operators (correct refutation), but also "supports: eval is used", and the aggregator
    turned the pair into `neutral`.
  - Context window: `data-export.component.ts:58` Sol `supports` XSS while its own claim says the source is
    unknown (it is the server's captcha image, a trusted source). Reverse tabnabbing (4, Luna) `supports`
    where the PoC found it mitigated.
- **Escalation cost vs value:** 40/89 Luna calls escalated (30 low confidence, 9 unparseable, 1 bad citation).
  Sol changed the answer in 11 (10 neutral->refutes, 1 ->non_security) and stayed neutral in 29, 19 of them
  credentials that no model can decide. Escalations were about 25% of run time.
- Codex output shows an encoding artifact (`expression�s`): the last-message file is probably not UTF-8 on
  Windows. It affects statement text only, not citation checks.

## Luna vs Sol comparison (2026-09-28, `data/runs/20260928-ab-routed/` vs `20260928-ab-sol/`)

Both runs used schema-enforced output and no credential low-confidence escalation, with the same prompt (assess-v1).
- The fixes worked: escalations fell from 40 to 8 (6 low confidence, 2 conflicting claims), with 0 unparseable
  and 0 rejected citations in either run.
- **Footer token counts (not comparable across models):** Luna averaged about 8.6k per call and Sol about 3.9k.
  Whole run: routed 139 calls / 1.27M vs Sol-only 131 calls / 0.83M. See the measured split below: the footer
  appears to count only uncached input plus output, so it tracks cache hits, not model effort.
- **Time:** about equal (Luna 8.1 s, Sol 8.6 s per fresh call); routed 20 min wall, Sol-only about 19 min.
- **Quality on Luna-first clusters:** PoC agreement routed 8 vs Sol 10 (4 vs 6 excluding runtime-only classes).
  Of 36 stance differences, 24 are quality findings where both tiers are inconsistent (stance semantics,
  item 1 below); the credential differences split 5 to routed, 6 to Sol.
- **Prices (per 1M tokens, given by the user 2026-09-28):** Sol $2 input / $0.20 cached input ($0.01 on some
  tier setups) / $10 output. Luna $0.10 / $0.01 / $0.50.
- **Measured usage** (`codex exec --json`, the same 8 current prompts through both models,
  `data/review/usage-sample.json`): per call, Luna 23,969 input (20,224 cached), 205 output; Sol 24,236 input
  (21,344 cached), 238 output; 0 reasoning tokens for both. About 20k of the input is Codex's own
  system prompt, served from cache; our prompt is about 3-4k.
- **Cost:** Luna 0.068 cents per call; Sol 1.22 cents (standard cache price) or 0.81 cents (low-tier cache).
  Recomputed 2026-10-04 from the token counts above: Sol 1.24 cents, or 0.84 cents low-tier.
  Run of 131 clusters: routed (89 Luna + 50 Sol calls) $0.67 vs Sol-only $1.60 (42%), or $0.47 vs $1.06 (44%)
  on the low-tier cache price.
- **Decision history:** Sol-only was chosen first on footer token counts, with the explanation that "Luna
  reasons longer". That explanation was wrong: measured reasoning tokens are 0 and input is nearly identical.
  **Routing is the default**, at about 42-44% of Sol-only cost. The quality gap (2 of 89 clusters) is within
  noise; recheck it after the stance-semantics fix.
- Codex overhead dominates: about 20k of the ~24k input per call is Codex's system prompt, not ours.
  A direct API client would cut input about 6x (see item 9).

## Work laptop: LiteLLM gateway instead of personal Codex (noted 2026-10-01, not built)

After the move to the company's enterprise GitHub, personal Codex is not available. The company LiteLLM gateway
(models hosted on Vertex, Bedrock, etc.) replaces it.
- Known on the gateway: **GPT-5.6 Luna and GPT-5.6 Sol**. GPT-6 is not confirmed yet (maybe later).
  Alternatives: Claude Opus / Sonnet / Haiku.
- Plan: add `--client litellm` (OpenAI-compatible `/chat/completions`, reuse `OpenAICompatibleClient`), with
  routing on as for codex; URL/key from `FVA_LITELLM_URL` / `FVA_LITELLM_KEY` (never logged); tiers via
  `FVA_MODEL_JUNIOR` / `FVA_MODEL_SENIOR` / `FVA_MODEL_ASTRA` set to the gateway's aliases.
- Needs: JSON-schema `response_format` with a fallback, real `usage` tokens + dollar estimate (closes item 8),
  retry/backoff on 429/5xx, corporate CA bundle support.
- Gains: no ~20k-token Codex system prompt (item 9), model name from the response, company-approved data path.
- Before relying on it: re-run the routed A/B against the PoC ledger on the gateway models (Luna/Sol results
  from GPT-6 do not carry over), and confirm gateway logging/retention in the data-handling sign-off.
- Ask the gateway owner: exact model aliases, and whether JSON-schema output is enabled per model.

## Historical backlog

Done 2026-09-28: structured output (`--output-schema`), no low-confidence escalation for credential CWEs,
token accounting per call and tier, routed vs Sol-only comparison (routing stays the default on price).

1. Stance semantics: tell the model that restating the scanner's sink is `neutral`, and that a real quality
   issue is `non_security`. Consider aggregation where a cited refutation of the precondition beats a
   restated sink. Bump `PROMPT_VERSION`. This is the main remaining source of disagreement.
   Done in `assess-v2` (PLAN.md T5).
2. Credential CWEs: `--credential-model skip` exists (opt-in, 2026-10-02). Score both modes on the real export,
   then decide the default. Scored 2026-10-04 (`docs/plans/unblocked-backlog.md` item 1): `ask` kept as the default.
3. SCA prompts: include advisory text, affected function, and config/usage sites so precondition checks are possible.
   Done: the prompt has the advisory description and call/import-site code windows; affected function names reach
   it through call-site evidence, which covers lodash and sanitize-html only.
4. Runtime harness: allowlist and approval gate before any probe.
5. Verdict reasoner, exports (ledger, enriched SARIF, report), benchmark against the PoC ledger. Partial: verdicts,
   worksheet, triage, report, `fva score`; SARIF in PR #33; no standalone verdict ledger file.
6. Done 2026-10-02: `.gitattributes` (`* text=auto`).
7. Evaluate Jev (TypeSafe AI, early access since 2026-09-15) as a routing/triage classifier, not an assessor.
   Jev returns typed choices with calibrated confidence and no text, so it cannot produce the cited claims the
   assessor requires, and its output is never evidence. Candidate uses: a Choice per cluster of
   skip-model / Luna / Sol, or predicting which Luna answers will escalate (8 of 89 after the fixes).
   Test: score Jev's calibration against the 130 PoC-labelled clusters before wiring it in.
   Gate: SaaS only, and its data retention, training use and input limits are undocumented. Complete a vendor
   data-handling review before sending anything, even redacted code (CLAUDE.md: only redacted code leaves the machine).
8. Exact cost accounting: record input, cached-input and output tokens per call and a per-run dollar estimate
   from configured prices. The current `tokens` field is Codex's footer, which is not total usage (see the
   comparison above). `codex exec --json` has the split but not the model name; find a way to get both.
9. Consider an API client for GPT-6 (OpenAI-compatible) to drop Codex's ~20k-token system prompt per call. Only
   worth it if API billing is acceptable versus the subscription, because at list prices a run already costs under $1.
   Costed 2026-10-04 (`docs/plans/unblocked-backlog.md` item 4): about $0.56 vs $0.68 per fresh run; not built.

## Milestone tasks — model estimate

Which Claude model each remaining [ROADMAP](ROADMAP.md) task likely needs to implement well.
**Opus**: design judgement, security reasoning, ambiguous matching, invariants that must not break.
**Sonnet**: well-specified code following existing patterns. **Haiku**: mechanical edits only.

| Milestone | Task | Model | Why |
|---|---|---|---|
| Pre-work | Move repo to company GitHub account | Haiku | Remote/URL updates only |
| Pre-work | Confirm data-handling rules for real Polaris data | Sonnet | Draft checklist; humans decide |
| v0.2 | Audit rejection of malformed inputs (raw exports untouched) ✅ | Sonnet | Tests against existing adapters |
| v0.4 | Polaris DAST adapter (URL, method, parameter, CWE, redacted req/resp) ✅ | Sonnet | Mirrors `fva/adapters/polaris.py`; redaction via `fva/redact.py` |
| v0.4 | SAST↔DAST linking by CWE, route/handler, parameter, with link confidence ✅ | Opus | Fuzzy route↔handler matching; false links mislead verdicts |
| v0.4 | SCA↔SAST linking via vulnerable-function call sites ✅ | Opus | Advisory-to-function mapping, reachability semantics |
| v0.4 | Grouped issue record keeping every original finding ✅ | Sonnet | Schema extension in `fva/schemas.py` |
| v0.4 | Assessor uses linked DAST as runtime evidence; no-hit never demotes ✅ | Opus | Touches `fva/invariants.py` verdict rules |
| v0.4 | Runtime mode setting (`none`, `dast-evidence`, `live-localhost`) ✅ | Haiku | Config flag plus guard |
| v0.5 | Per-application runtime profile (start, health, base URL, stop) | Sonnet | Straightforward harness |
| v0.5 | Safe HTTP/browser probes, localhost test apps only | Opus | Safety boundary; must not over-reach |
| v0.5 | Redacted evidence receipts and negative controls | Sonnet | Reuses provenance/redaction |
| v0.5 | Human approval gate for intrusive tests; no crash/DoS tests | Opus | Security-critical policy |
| v0.6 | Verdicts with confidence and reason codes per grouped issue | Opus | Core decision logic |
| v0.6 | Evidence-based priority ranking | Opus | Weighting design and justification |
| v0.6 | One remediation ticket per grouped issue | Sonnet | Templating from grouped record |
| v0.6 | Deterministic JSONL output and human-readable report | Sonnet | Serialization and formatting |
| v0.6 | Enriched SAST/SCA/DAST SARIF, kept separate | Sonnet | SARIF spec work, existing adapter knowledge |
| v0.6 | Approval-gated comment and triage previews | Sonnet | Preview only, no writes |
| v0.7 | Independently adjudicated multi-app benchmark | Opus | Ground-truth judgement |
| v0.7 | Metrics: queue reduction, precision, unresolved, incorrect demotions | Sonnet | Computation over ledgers |
| v0.7 | Measure SAST↔DAST link accuracy | Sonnet | Metric over labelled links |
| v0.7 | Measure scanner-gap discoveries separately | Opus | Judging novel findings |
| v0.7 | Document model/prompt/tool/source/runtime versions | Haiku | Recording metadata |
| Open | Live model-assessor run on Juice Shop vs PoC ledger | Opus | Reasoning quality is what's measured |
| Open | `.gitattributes` for line endings | Haiku | One-line file |

Totals: 10 Opus, 12 Sonnet, 4 Haiku. The model used *inside* the agent for assessment (`fva/reasoning/`) is a separate choice.
