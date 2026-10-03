# Checkpoint

Last updated: 2026-10-02. Update this file at every commit that changes status.

## Resume here

- 2026-10-02, `codex/blind-evaluation-pilot`: implementing the attached blind pilot plan.
  External `--profile-file` and `eval prepare` source/profile preflight are available.
  Preflight records each file's boundary rule, import reachability, dependency inventory,
  pinned source/profile hashes and the existing Express route map. Expected routes are
  required for DAST readiness; missing/incorrect handlers block launch.
  Final clean source and hosted metadata have arrived in the neutral handoff directory.
  Verified source commit `7707c673bb709e7d820fd8dd2980e83b1f133db0`, clean tracked tree,
  content SHA256 `52a2ffe9bf4742e809cece3fcca866e4e40f5222ab1d2f8b6414db3f02df705d`.
  No private ledger has been read. SAST/SCA/DAST remain NOT_LAUNCHED pending project setup.
  Source-only preflight accepts explicitly selected external report output; source
  overlap, Git metadata, escaped report paths and frozen runs are rejected. Discovery
  and paired evaluation artifacts still require ignored data/.
  Preliminary preflight completed with the app session's neutral handoff inputs.
  Reports: `C:\TestCode\fva-eval-private\handoff\preliminary-preflight\preflight.json`
  and `preflight.md`. Route readiness passed; this is preliminary, not authorization
  to launch scans. No discovery/model/scanner call or private ledger read occurred.
  Discovery attempts are in ignored `data/eval/record-desk-discovery-01` and `-02`.
  Attempt 01 could not access Codex home under the sandbox. Attempt 02 ran with the
  user login but the CLI endpoint rejected requested `gpt-6.1-sol` for its ChatGPT
  account; no model answer exists and no substitute was used. Both failures are retained.
  The packet contains six tracked code/manifest files and 69 installed packages, with
  no scanner results, route expectations, handoff history, private receipts or credential.
  A Git inventory failure previously caused an unsafe archive fallback with untracked
  files. Source pinning now uses a scoped safe.directory and refuses that fallback.
  Model-call failures are retained as processing-failure.json; audit state resets per call.
  Next discovery step: explicit user authorization for a fresh in-app Sol 6.1 subagent,
  or correction of CLI model access. The prepared source-only packet is ready; neither
  candidate discovery nor paired assessment is complete. Do not report zero discoveries.
  Discovery and frozen paired prepare/run/score tooling are now implemented. See
  `docs/blind-pilot.md` for exact invocations and file contracts. Fixed `gpt-6.1-sol`
  calls audit tool events and require observed identity; no routing/cache in evaluation.
  The smoke response is reused in the batch. Source/profile/export hashes bind human
  link approval. Private gold remains absent from preparation/run and model inputs;
  a label-free receipt freezes its hash before the smoke. One raw response feeds all
  three arms. Explicit case gold and legacy key formats both work. Counts only; no judge.
  Verification: local dev environment installed; 228 passed, 5 skipped on Windows.
  Private-data/source tests and POSIX-only CLI stand-ins are among the skips.
  A source pinning fix prevents an archive nested under another Git checkout from
  accidentally using its parent's tracked-file inventory. Tests run under ignored data/.
  Next application-session inputs: tracked demo source, external DeploymentProfile,
  expected method/path/handler list, and resolved inventory. Run source-only preflight
  first. Then discover, census actual Polaris exports, prepare/review links, re-prepare
  approved packets, freeze private labels and their receipt, smoke, batch, human-grade,
  score. Fresh discovery was attempted but returned no answer; no actual evaluation result exists.
  Real DAST ingestion validation remains blocked on an actual export sample. Do not
  reinterpret fixture tests as real DAST verification. Rejected true discoveries and
  missed verified plants remain unmeasured until private human reconciliation.
  Tokenomics: parent runtime verified Sol 6.1 medium; bounded read-only interface
  collection requested Luna and observed `gpt-6-luna` in its matching session metadata.
  Source review was usable; integration/final review remained in Sol. No savings measured.
  Review: draft PR #9, https://github.com/tonesjones/finding-validation-agent/pull/9.
  Implementation commit `ebd99d7` passed all Linux/Windows CI jobs on Python 3.10/3.12.

- 2026-10-02 (branch `claude/compassionate-ramanujan-vjgzq0`, after a whole-project review):
  - **Rule closures now cite evidence.** Before, 430 of 573 worksheet rows were closed `not_applicable` with no evidence
    record. Skipped findings now keep a `deployment_boundary` record (path rule) or their `dependency_resolution` /
    reachability records, and the closure passes `check_verdict`. Prompts are unchanged, so **re-run `assess` on the
    real export (all cache hits, free), then `worksheet` and `score`**: expect the same 430 `not_applicable`, each
    with `evidence_ids`. Older run dirs now show those rows as needs_review, with a warning.
  - Verdict suggestion logic moved to `fva/verdicts.py` (worksheet and score import it).
  - `assess --workers N` (parallel model calls, ordered output), `--credential-model skip` (opt-in; compare with
    `score` against `ask` before making it the default), missing-lockfile warning. CI on Linux + Windows.
  - **No DAST exists in the PoC tenant.** The DAST adapter, SAST↔DAST linker and DAST evidence are frozen and
    unverified (built from a guessed format).
  - Polaris data tools (built, tested on fixtures/stubs, not yet run on live data): `python -m fva.polaris_mcp
    inventory`, `python -m fva census <dir>`, `python -m fva correlation-value --source <checkout>`.
    **Next action once Polaris access is back:** run inventory + census (anywhere), then correlation-value on the
    laptop (needs the PoC ledger), and record the tables here. Cloud sessions read `POLARIS_ACCESS_TOKEN` from the
    environment settings.
  - README restructured (plain-language top, built vs planned), operator detail moved to `docs/operations.md`,
    PROJECT_STATUS.md removed (status lives here).
- PRs #4, #5 and #6 are merged into `main` (v0.4 + routing). **Luna/Sol routing is the default** for codex;
  `--no-route` or `--model` runs one model.
- 2026-10-01 (branch `claude/stoic-shannon-3wy7sq`): scanner mix without DAST, `likely` verdict, triage worksheet
  and review re-import (see "Scanner mix and write-back" below). Not yet run on the real Juice Shop export:
  run `assess` locally, then `python -m fva worksheet <run_dir>`.
- First real worksheet (`data/runs/20261001-153602-codex/`): 573 rows, 499 issues; 430 not_applicable,
  42 likely, 99 needs_review, 2 valid_non_security. Next: `python -m fva score <run_dir>` (added 2026-10-01).
- **Next action:** "Open / next" items 1-2 (stance semantics, SCA advisory context), then a routed re-run
  compared against `data/runs/20260928-ab-routed/` (baseline for the current prompt; Sol-only baseline
  `data/runs/20260928-ab-sol/`).
- Review scripts (local, not committed): `python data/review/review_run.py <run_dir>`,
  `python data/review/compare_ab.py <routed_run> <sol_run>`,
  `python data/review/measure_usage.py <dry_run_dir> <n>` (exact token split via `codex exec --json`).
- Caveat: the per-call `tokens` field in run summaries is Codex's footer count, not total usage; use
  `measure_usage.py` figures for cost (item 8).

## Built (package `fva`, Python >= 3.10, tests: `python -m pytest`)

| Area | Module | Status |
|---|---|---|
| Canonical schemas | `fva/schemas.py` | IngestionRun, Finding, EvidenceRecord (many findings per record), DeploymentProfile, Verdict (append-only, `supersedes`) |
| Reason codes | `fva/reason_codes.py` | Vocabulary v1: 26 codes (4 appended 2026-10-01: 2 `likely`, 2 reviewer); 16 map 1:1 from the PoC |
| Verdict invariants | `fva/invariants.py` | confirmed needs `supports`, not_applicable needs `refutes`, conflict forces needs_review; `likely` needs `supports` plus rule-derived static evidence |
| Scanner mix | `fva/pipeline.py`, `fva/runtime_mode.py` | any mix; no DAST -> runtime mode `none`; SCA↔SAST and SAST↔DAST links + groups wired in; `findings.jsonl` indexes every original finding |
| Automatic scoring | `fva/export/score.py` | `python -m fva score <run>` vs PoC ledger: agreement, incorrect demotions, unresolved, queue reduction, by tier/scanner -> `score.md/json`, `score_rows.csv` |
| Triage worksheet | `fva/export/` | `worksheet.csv/.html` per Polaris issue id; suggestions pass invariants; `import-review` -> `human_review` evidence, superseding verdicts, agreement score |
| Suggested verdicts | `fva/verdicts.py` | rules over a run's evidence; every closure, rule closures included, must pass `check_verdict` |
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
| DAST adapter | `fva/adapters/polaris.py` (`load_dast`) | DAST issues -> Finding with `EndpointRef` (app-relative path only, host dropped); redacted 500-char snippets; envelope ASSUMED until a real sample exists |
| Runtime mode | `fva/runtime_mode.py` | `none` / `dast-evidence` (default) / `live-localhost` (http(s) localhost targets only) |
| SAST↔DAST links | `fva/correlation/runtime_link.py` | Express route table + CWE + parameter near sink; high/medium/low |
| SCA↔SAST links | `fva/correlation/package_link.py` | shipped import in the SAST file + CWE; test-only imports never link |
| Grouping | `fva/correlation/grouping.py` | connected components; every finding kept; SAST primary |
| DAST evidence | `fva/correlation/dast_evidence.py` | only high-confidence links `support`; no DAST hit = no evidence; reason code `DAST_OBSERVED` |

## Decisions

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
- Cloud workspace can now reach `poc.polaris.blackduck.com` (allowlisted 2026-09-27).

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
  claims, low self-reported confidence, or Luna `refutes` a high/critical finding. No further retries.
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

## Open / next

Done 2026-09-28: structured output (`--output-schema`), no low-confidence escalation for credential CWEs,
token accounting per call and tier, routed vs Sol-only comparison (routing stays the default on price).

1. Stance semantics: tell the model that restating the scanner's sink is `neutral`, and that a real quality
   issue is `non_security`. Consider aggregation where a cited refutation of the precondition beats a
   restated sink. Bump `PROMPT_VERSION`. This is the main remaining source of disagreement.
2. Credential CWEs: `--credential-model skip` exists (opt-in, 2026-10-02). Score both modes on the real export,
   then decide the default.
3. SCA prompts: include advisory text, affected function, and config/usage sites so precondition checks are possible.
4. Runtime harness: allowlist and approval gate before any probe.
5. Verdict reasoner, exports (ledger, enriched SARIF, report), benchmark against the PoC ledger.
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

## Milestone tasks — model estimate

Which Claude model each remaining [ROADMAP](ROADMAP.md) task likely needs to implement well.
**Opus**: design judgement, security reasoning, ambiguous matching, invariants that must not break.
**Sonnet**: well-specified code following existing patterns. **Haiku**: mechanical edits only.

| Milestone | Task | Model | Why |
|---|---|---|---|
| Pre-work | Move repo to company GitHub account | Haiku | Remote/URL updates only |
| Pre-work | Confirm data-handling rules for real Polaris data | Sonnet | Draft checklist; humans decide |
| v0.2 | Audit rejection of malformed inputs (raw exports untouched) | Sonnet | Tests against existing adapters |
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
