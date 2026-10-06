# Roadmap

The end goal is described in the [README](README.md#what-this-tool-does): one evidence-backed,
prioritized issue per real flaw, built from Polaris SAST, SCA, and DAST results.

## Pre-work — Repository migration

- [ ] Move this repository to a company GitHub account.
- [ ] Confirm data-handling rules for Polaris exports and customer source before
      ingesting any real (non-test) results.

## v0.1 — Publish the experiment

- [x] State the hypothesis and evidence model.
- [x] Document the Juice Shop experiment and its limitations.
- [x] Add sanitized example input and output records.
- [x] Publish this clean project shell to GitHub.

## v0.2 — Vendor-neutral intake

- [x] Define the canonical finding and evidence-ledger schemas.
- [x] Add a SARIF 2.1.0 input adapter.
- [x] Extract the observed Polaris SAST/SCA export adapter from the proof of concept.
- [x] Add a Polaris MCP adapter for raw issue responses.
- [x] Add a simple declarative CSV/JSON field-mapping adapter.
- [x] Reject malformed inputs without modifying the raw exports (audit coverage, `tests/test_adapter_malformed.py`).

## v0.3 — Source and deployment analysis

- [x] Pin source revision and record repository state.
- [x] Locate source evidence and deployment boundaries.
- [x] Reconcile SCA findings with the resolved dependency snapshot.
- [x] Record reachability claims separately from runtime observations.

## v0.4 — DAST evidence and cross-scanner grouping (done)

On 2026-10-03 the DAST importer was checked against six real issue details from a
separate sample project, and repaired. That verifies the sampled endpoint and type
mappings. It doesn't verify request and response retrieval or cross-scanner links for
the pilot app, whose DAST scan waits on entitlement. The items below are implementation
status.

- [x] Polaris DAST adapter: URL, method, parameter, CWE, redacted request/response.
- [x] SAST↔DAST linking by CWE, route/handler, and parameter, with link confidence.
- [x] SCA↔SAST linking via shipped import sites in the SAST file (file-level).
- [ ] Refine SCA↔SAST linking to call sites of the vulnerable function. Partial: call-site evidence and
      closures for 5 lodash advisories and sanitize-html options (`fva/correlation/advisory_applicability.py`);
      the links themselves stay file-level.
- [x] Grouped issue record that keeps every original finding and its evidence.
- [x] Assessor treats a linked DAST observation as runtime evidence; absence of a
      DAST hit never demotes a finding.
- [x] Runtime mode setting: `none`, `dast-evidence` (default), `live-localhost`.

## v0.5 — Optional live validation (test targets only)

Web apps only. SAST+SCA-only scans (non-web apps, no DAST) run in runtime mode `none` and rely on
`likely` plus human review instead.

- [ ] Per-application runtime profile: start, health check, base URL, stop. Not built: the operator starts the app.
- [ ] Safe HTTP/browser probes restricted to localhost, intentionally vulnerable apps. Partial: approved
      loopback GET pairs (`fva/runtime.py`); no browser probes.
- [ ] Store redacted evidence receipts and negative controls. Partial: source-bound receipts and
      `negative_control` evidence exist, but receipts keep response bodies unredacted on disk (never sent to
      models or tickets).
- [x] Require human approval for intrusive tests; exclude crash and denial-of-service tests (`runtime approve`,
      GET only, bounded pairs, time and size; `tests/test_runtime_collector.py`).

## v0.6 — Decisions, prioritization, and remediation output

- [x] Any scanner mix: SAST+SCA without DAST is a first-class run (scanner mix and runtime mode in `summary.json`).
- [x] `likely` verdict for strong static evidence; never confirmed without runtime or human evidence.
- [x] Triage worksheet (CSV + HTML), one row per Polaris issue id, with suggested triage status and severity.
- [x] Re-import a filled worksheet: reviewer decisions become `human_review` evidence and superseding verdicts,
      plus an agreement score per suggested verdict.
- [x] Every rule closure cites its evidence (deployment boundary, dependency resolution).

- [ ] Evidence-backed verdicts with confidence and reason codes per grouped issue. Partial: per finding
      (`fva/triage.py`); tickets roll codes and evidence up per issue but carry no issue-level confidence.
- [x] Evidence-based priority ranking (verdict × reachability × runtime evidence × severity) (`fva/export/report.py`).
- [ ] One remediation ticket per grouped issue: fix location, route, DAST request, linked findings. Partial:
      `tickets.jsonl` has the location and linked findings; no HTTP route or DAST request yet.
- [x] Deterministic JSONL output and human-readable report (`fva report`: tickets.jsonl, report.md, report.html).
- [ ] Enriched Polaris-ready SAST, SCA, and DAST SARIF, kept separate. Partial: `fva sarif` (PR #33) writes one
      file per scanner type; Polaris import is unverified and DAST waits on the entitlement.
- [x] Approval-gated platform comment and triage previews (`fva preview`, PR #34; dry run, label map ASSUMED).

## v0.7 — Evaluation

- [ ] Independently adjudicated benchmark across multiple applications.
- [ ] Measure queue reduction, precision improvement, unresolved rate, and incorrect demotions. Partial:
      `fva score` has all but precision.
- [ ] Measure SAST↔DAST link accuracy.
- [ ] Measure scanner-gap discoveries separately.
- [x] Document model, prompt, tool, source, and runtime versions for reproducibility (`summary.json`
      `versions` block, plus model and prompt version).
- [ ] Evaluate TypeSafe AI's Jev (typed decisions with calibrated confidence, no text) as a triage and routing
      step: skip / junior / senior per cluster, or predict junior escalation. Never as evidence, because Jev
      produces no citations. Gate: vendor data-handling review before sending even redacted code.

## v0.8 — Approval-gated Polaris write-back

The Polaris MCP server is read-only, so re-ratings and groupings cannot go back through it.
- [ ] Confirm the Polaris REST endpoints for triage status, severity and comments; verify the
      `fva/export/polaris_triage_map.py` labels (currently ASSUMED).
- [ ] Separate writer module with its own write-scoped token, never on the MCP read-only allowlist.
- [ ] Input is an approved worksheet only; dry-run diff by default; per-run human approval; idempotent;
      before/after audit log for every write.
- [ ] Groupings as comments or tags, since Polaris has no cross-scanner group object (to verify).
- Gate: company GitHub, data-handling sign-off, customer consent; update the CLAUDE.md read-only rule when it lands.

## Not now

- A hosted multi-tenant service
- Automatic remediation
- Automatic triage changes in commercial platforms
- Live testing of customer applications without explicit consent
- Dozens of scanner-specific integrations
- Claims of exhaustive or fully autonomous security testing
