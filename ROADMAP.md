# Roadmap

## v0.1 — Publish the experiment

- [x] State the hypothesis and evidence model.
- [x] Document the Juice Shop experiment and its limitations.
- [ ] Add sanitized example input and output records.
- [ ] Publish this clean project shell to GitHub.

## v0.2 — Vendor-neutral intake

- [ ] Define the canonical finding and evidence-ledger schemas.
- [ ] Add a SARIF 2.1.0 input adapter.
- [ ] Extract the observed Polaris SAST/SCA export adapter from the proof of concept.
- [ ] Add a simple declarative CSV/JSON field-mapping adapter.
- [ ] Reject malformed inputs without modifying the raw exports.

## v0.3 — Source and deployment analysis

- [ ] Pin source revision and record repository state.
- [ ] Locate source evidence and deployment boundaries.
- [ ] Reconcile SCA findings with the resolved dependency snapshot.
- [ ] Record reachability claims separately from runtime observations.

## v0.4 — Safe runtime validation

- [ ] Define a per-application runtime profile: start, health check, base URL, stop.
- [ ] Add safe HTTP/browser probes with allowlisted targets and budgets.
- [ ] Store redacted evidence receipts and negative controls.
- [ ] Require human approval for intrusive tests; exclude crash and denial-of-service tests.

## v0.5 — Decisions and outputs

- [ ] Produce evidence-backed verdicts with confidence and reason codes.
- [ ] Generate reports and deterministic JSONL output.
- [ ] Generate enriched Polaris-ready SAST and SCA SARIF separately.
- [ ] Add approval-gated platform comment and triage previews.

## v0.6 — Evaluation

- [ ] Add an independently adjudicated benchmark across multiple applications.
- [ ] Measure precision improvement, unresolved rate, and incorrect demotions.
- [ ] Measure scanner-gap discoveries separately.
- [ ] Document model, prompt, tool, source, and runtime versions for reproducibility.

## Not now

- A hosted multi-tenant service
- Automatic remediation
- Automatic triage changes in commercial platforms
- Dozens of scanner-specific integrations
- Claims of exhaustive or fully autonomous security testing
