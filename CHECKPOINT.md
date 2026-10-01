# Checkpoint

Last updated: 2026-10-01. Update this file at every commit that changes status.

## Built (package `fva`, Python >= 3.10, tests: `python -m pytest`)

| Area | Module | Status |
|---|---|---|
| Canonical schemas | `fva/schemas.py` | IngestionRun, Finding, EvidenceRecord (many findings per record), DeploymentProfile, Verdict (append-only, `supersedes`) |
| Reason codes | `fva/reason_codes.py` | Vocabulary v1: 22 codes; 16 map 1:1 from the Juice Shop PoC classifications |
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
| Polaris raw-issue adapter | `fva/adapters/polaris.py` (`load_mcp`) | reads get_issue / list_issues responses; package identity from `component-origin-external-id`; drops internal links/tenant id |
| DAST adapter | `fva/adapters/polaris.py` (`load_dast`) | DAST issues -> Finding with `EndpointRef` (app-relative path only, host dropped); redacted 500-char snippets; envelope ASSUMED until a real sample exists |
| Runtime mode | `fva/runtime_mode.py` | `none` / `dast-evidence` (default) / `live-localhost` (http(s) localhost targets only) |
| SAST↔DAST links | `fva/correlation/runtime_link.py` | Express route table + CWE + parameter near sink; high/medium/low |
| SCA↔SAST links | `fva/correlation/package_link.py` | shipped import in the SAST file + CWE; test-only imports never link |
| Grouping | `fva/correlation/grouping.py` | connected components; every finding kept; SAST primary |
| DAST evidence | `fva/correlation/dast_evidence.py` | only high-confidence links `support`; no DAST hit = no evidence; reason code `DAST_OBSERVED` |

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
- Cloud workspace can now reach `poc.polaris.blackduck.com` (allowlisted 2026-09-27).

## Juice Shop reachability results (2026-09-27)

- Import graph from `server.ts`, `app.ts`, `frontend/src/main.ts`: 640 code files, 285 reachable.
- All 85 production SAST code findings sit in the entrypoint graph; the other 30 are non-code (e.g. `data/static/users.yml`).
- All 12 vulnerable SCA packages are imported by reachable code, so import-level reachability does not separate
  Juice Shop's SCA findings. The PoC separated them by version drift (built) and advisory preconditions (model step).

## Open / next

1. Run the model assessor live on Juice Shop production findings and measure agreement with the PoC ledger
   (needs `ANTHROPIC_API_KEY` or a local model endpoint). Cluster findings that share a sink before calling the model.
2. Runtime harness: allowlist and approval gate before any probe.
3. Verdict reasoner, exports (ledger, enriched SARIF, report), benchmark against the PoC ledger.
4. Consider a `.gitattributes` (`* text=auto`) so Windows line endings stop showing as modifications.

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
