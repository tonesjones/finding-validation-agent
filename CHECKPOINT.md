# Checkpoint

Last updated: 2026-09-27. Update this file at every commit that changes status.

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
| Polaris raw-issue adapter | `fva/adapters/polaris.py` (`load_mcp`) | reads get_issue / list_issues responses; package identity from `component-origin-external-id`; drops internal links/tenant id |

## Decisions

- SAST engine is Polaris only (no Semgrep/CodeQL).
- The model never produces `confirmed` on its own; it emits cited evidence, rules decide verdicts.
- Model step must be swappable for a local model.
- Confidence is `high | medium | low`.
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

## Open / next

1. Reachability layer: built-in checks (import usage, route wiring) + model evidence with verified citations.
2. Runtime harness: allowlist and approval gate before any probe.
3. Verdict reasoner, exports (ledger, enriched SARIF, report), benchmark against the PoC ledger.
4. Consider a `.gitattributes` (`* text=auto`) so Windows line endings stop showing as modifications.
