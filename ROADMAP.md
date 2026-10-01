# Roadmap

The end goal is described in the [README](README.md#end-result): one evidence-backed,
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

## v0.4 — DAST evidence and cross-scanner grouping (next)

- [ ] Polaris DAST adapter: URL, method, parameter, CWE, redacted request/response.
- [ ] SAST↔DAST linking by CWE, route/handler, and parameter, with link confidence.
- [ ] SCA↔SAST linking via call sites of the vulnerable dependency function.
- [ ] Grouped issue record that keeps every original finding and its evidence.
- [ ] Assessor treats a linked DAST observation as runtime evidence; absence of a
      DAST hit never demotes a finding.
- [ ] Runtime mode setting: `none`, `dast-evidence` (default), `live-localhost`.

## v0.5 — Optional live validation (test targets only)

- [ ] Per-application runtime profile: start, health check, base URL, stop.
- [ ] Safe HTTP/browser probes restricted to localhost, intentionally vulnerable apps.
- [ ] Store redacted evidence receipts and negative controls.
- [ ] Require human approval for intrusive tests; exclude crash and denial-of-service tests.

## v0.6 — Decisions, prioritization, and remediation output

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
- [ ] Document model, prompt, tool, source, and runtime versions for reproducibility.

## Not now

- A hosted multi-tenant service
- Automatic remediation
- Automatic triage changes in commercial platforms
- Live testing of customer applications without explicit consent
- Dozens of scanner-specific integrations
- Claims of exhaustive or fully autonomous security testing
