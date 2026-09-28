# Checkpoint

Last updated: 2026-09-27 (session 2). Update this file at every commit that changes status.

## Resume here

- Branch `feat/cli-assess` (PR #4, open): routing built, reviewed, then compared against Sol-only.
  **Decision (2026-09-28): Sol-only is the default**; Luna/Sol routing is opt-in with `--route`.
  PR #4 not merged yet: the user decides.
- **Next action:** "Open / next" items 1-2 (stance semantics, SCA advisory context), then a Sol-only re-run
  compared against `data/runs/20260928-ab-sol/` (baseline for the current prompt).
- Review scripts (local, not committed): `python data/review/review_run.py <run_dir>`,
  `python data/review/compare_ab.py <routed_run> <sol_run>`.

## Built (package `fva`, Python >= 3.10, tests: `python -m pytest`)

| Area | Module | Status |
|---|---|---|
| Canonical schemas | `fva/schemas.py` | IngestionRun, Finding, EvidenceRecord (many findings per record), DeploymentProfile, Verdict (append-only, `supersedes`) |
| Reason codes | `fva/reason_codes.py` | Vocabulary v1: 21 codes; 16 map 1:1 from the Juice Shop PoC classifications |
| Verdict invariants | `fva/invariants.py` | confirmed needs `supports`, not_applicable needs `refutes`, conflict forces needs_review |
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

## Decisions

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
- Superseded default: routing was on for codex at first; since 2026-09-28 it is opt-in (`--route`). `--astra <source_finding_id>`
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
- **Tokens:** on the 89 Luna-first clusters, Luna averaged about 8.6k tokens per call and Sol about 3.9k.
  Whole run: routed 139 calls / 1.27M tokens vs Sol-only 131 calls / 0.83M (-35%).
- **Time:** about equal (Luna 8.1 s, Sol 8.6 s per fresh call); routed 20 min wall, Sol-only about 19 min.
- **Quality on Luna-first clusters:** PoC agreement routed 8 vs Sol 10 (4 vs 6 excluding runtime-only classes).
  Of 36 stance differences, 24 are quality findings where both tiers are inconsistent (stance semantics,
  item 1 below); the credential differences split 5 to routed, 6 to Sol.
- **Decision:** Sol-only by default. Luna saves no tokens (Codex counts include reasoning; Luna reasons longer)
  and loses a little agreement. Revisit only if Luna's per-token quota price is under ~45% of Sol's, or
  after the prompt changes.

## Open / next

Done 2026-09-28: structured output (`--output-schema`), no low-confidence escalation for credential CWEs,
token accounting per call and tier, Sol-only default.

1. Stance semantics: tell the model that restating the scanner's sink is `neutral`, and that a real quality
   issue is `non_security`. Consider aggregation where a cited refutation of the precondition beats a
   restated sink. Bump `PROMPT_VERSION`. This is the main remaining source of disagreement.
2. Credential CWEs: consider skipping the model call entirely, because they are runtime-decided.
3. SCA prompts: include advisory text, affected function, and config/usage sites so precondition checks are possible.
4. Runtime harness: allowlist and approval gate before any probe.
5. Verdict reasoner, exports (ledger, enriched SARIF, report), benchmark against the PoC ledger.
6. Consider a `.gitattributes` (`* text=auto`) so Windows line endings stop showing as modifications.
7. Evaluate Jev (TypeSafe AI, early access since 2026-09-15) as a routing/triage classifier, not an assessor.
   Jev returns typed choices with calibrated confidence and no text, so it cannot produce the cited claims the
   assessor requires, and its output is never evidence. Candidate uses: a Choice per cluster of
   skip-model / Sol (Luna is no longer the default), or flagging clusters that need no model call.
   Test: score Jev's calibration against the 130 PoC-labelled clusters before wiring it in.
   Gate: SaaS only, and its data retention, training use and input limits are undocumented. Complete a vendor
   data-handling review before sending anything, even redacted code (CLAUDE.md: only redacted code leaves the machine).
