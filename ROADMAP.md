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
- [ ] Reject malformed inputs without modifying the raw exports (audit coverage).

## v0.3 — Source and deployment analysis

- [x] Pin source revision and record repository state.
- [x] Locate source evidence and deployment boundaries.
- [x] Reconcile SCA findings with the resolved dependency snapshot.
- [x] Record reachability claims separately from runtime observations.

## v0.4 — DAST evidence and cross-scanner grouping (done)

The Polaris test tenant has no DAST data (checked 2026-10-02): the DAST items below were built from a
guessed response format and stay frozen and unverified until a real DAST export exists.

- [x] Polaris DAST adapter: URL, method, parameter, CWE, redacted request/response.
- [x] SAST↔DAST linking by CWE, route/handler, and parameter, with link confidence.
- [x] SCA↔SAST linking via shipped import sites in the SAST file (file-level).
- [ ] Refine SCA↔SAST linking to call sites of the vulnerable function.
- [x] Grouped issue record that keeps every original finding and its evidence.
- [x] Assessor treats a linked DAST observation as runtime evidence; absence of a
      DAST hit never demotes a finding.
- [x] Runtime mode setting: `none`, `dast-evidence` (default), `live-localhost`.

## v0.5 — Optional live validation (test targets only)

Web apps only. SAST+SCA-only scans (non-web apps, no DAST) run in runtime mode `none` and rely on
`likely` plus human review instead.

- [ ] Per-application runtime profile: start, health check, base URL, stop.
- [ ] Safe HTTP/browser probes restricted to localhost, intentionally vulnerable apps.
- [ ] Store redacted evidence receipts and negative controls.
- [ ] Require human approval for intrusive tests; exclude crash and denial-of-service tests.

## v0.6 — Decisions, prioritization, and remediation output

- [x] Any scanner mix: SAST+SCA without DAST is a first-class run (scanner mix and runtime mode in `summary.json`).
- [x] `likely` verdict for strong static evidence; never confirmed without runtime or human evidence.
- [x] Triage worksheet (CSV + HTML), one row per Polaris issue id, with suggested triage status and severity.
- [x] Re-import a filled worksheet: reviewer decisions become `human_review` evidence and superseding verdicts,
      plus an agreement score per suggested verdict.
- [x] Every rule closure cites its evidence (deployment boundary, dependency resolution).

- [ ] Evidence-backed verdicts with confidence and reason codes per grouped issue.
- [ ] Evidence-based priority ranking (verdict × reachability × runtime evidence × severity).
- [ ] One remediation ticket per grouped issue: fix location, route, DAST request, linked findings.
- [ ] Deterministic JSONL output and human-readable report.
- [ ] Enriched Polaris-ready SAST, SCA, and DAST SARIF, kept separate.
- [ ] Approval-gated platform comment and triage previews.

## v0.7 — Evaluation

- [ ] Independently adjudicated benchmark across multiple applications.
- [ ] Measure queue reduction, precision improvement, unresolved rate, and incorrect demotions.
- [ ] Measure SAST↔DAST link accuracy.
- [ ] Measure scanner-gap discoveries separately.
- [x] Polaris data tools: MCP inventory, field census, correlation value of candidate join keys (built 2026-10-02).
- [ ] Run them on live Polaris data; decide which links to keep and which dropped fields the adapter should read.
- [ ] Document model, prompt, tool, source, and runtime versions for reproducibility.
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
