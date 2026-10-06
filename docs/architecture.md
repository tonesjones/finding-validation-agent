# Minimal architecture

FVA is a small pipeline for Polaris SAST and SCA exports and the matching source checkout.
It closes findings only with cited evidence and leaves the rest open in a ranked report.

```text
Polaris export  -> intake -> findings
source checkout -> source and deployment evidence
lockfile        -> dependency evidence
                       |
                 rules and model assessment
                       |
                    triage
                       |
              ranked report / JSONL / SARIF
```

## Core records

`Finding` keeps the original scanner id, rule, title, severity, location and package data.
`raw_evidence_ref` points to the hashed input record. Extra scanner fields stay in `scanner_metadata`.

`EvidenceRecord` records its type, method, stance, summary and covered finding ids.
Runtime evidence must name its deployment profile.

`Verdict` records the decision, confidence, reason codes, evidence ids and deployment profile.
It keeps the original finding. A later decision can name the verdict it supersedes.

`FindingLink` records why two findings describe the same issue.
`GroupedIssue` keeps every member id and names a primary finding.
A link shows identity, not exploitability.

## Input boundary

`fva.pipeline.load_findings` accepts saved Polaris MCP JSON exports.
For a single `.jsonl` or `.csv` path, it uses the flat Polaris mapping in `fva/adapters/polaris.py`.
It does not select the SARIF or generic mapping adapters for `assess`.
Polaris is the only scanner input.

## Assessment and output

1. Pin source content and record the checkout state.
2. Classify deployment surfaces and record evidence for rule closures.
3. Locate source, reconcile dependencies when a lockfile is supplied and check static reachability.
4. Link related findings and assess remaining clusters with redacted source.
5. Verify model citations against the pinned source.
6. Apply verdict invariants and triage checks.
7. Rank open issues and record `missing_evidence` for each open ticket.

The model never confirms. Model output alone cannot close a finding.
`likely` needs static rule evidence. `confirmed` needs supporting runtime, DAST or imported evidence.
The schema still retains `human_review` as a historical evidence type.
There is no review importer or routine human review step.
The internal `review` route means the finding stays open.
`HIGH_IMPACT_CLOSURE` keeps a high or critical closure open without high-confidence evidence.

## Runtime boundary

DAST is parked as optional evidence. It is not required for the normal SAST and SCA pipeline.
`assess` uses runtime mode `none` without DAST and `dast-evidence` when DAST findings are present.
It never starts live probes.

The separate `runtime` command supports an approved exact localhost GET plan.
It does not start, stop or health-check the app.
The operator must approve the plan in an interactive terminal before collection.
Probe confirmation needs verified receipts and a linked negative control for the same deployment.
Raw responses stay local and never go to models or tickets.
A failed probe or missing DAST result never proves a finding is safe.
See the [operations guide](operations.md#approved-localhost-runtime-collection) for the parked collector.
