# Minimal architecture

The project should remain a small pipeline with replaceable edges, not a large agent
platform.

```text
scanner export  ->  intake adapter  ->  canonical finding ledger
                                             |
source checkout ->  source evidence ---------+
dependency data ->  SCA reconciliation ------+-> decision engine
safe runtime    ->  runtime evidence --------+       |
                                                     +-> report / JSONL
                                                     +-> enriched SARIF
                                                     +-> review preview
```

## Core records

### Finding

The canonical finding keeps the original tool, identifier, rule, message, severity,
location, component/advisory data, and a hash of the raw source record. Tool-specific
fields remain available as namespaced metadata.

### Evidence

Each evidence item records what was observed, how it was obtained, the source or
runtime target, timestamp, redaction state, and whether it supports, contradicts,
or merely contextualizes the finding.

### Decision

A decision contains the verdict, confidence, reason codes, evidence references,
deployment scope, remaining uncertainty, and recommended next action. It must never
overwrite the original finding.

## Adapter boundary

Adapters translate data; they do not decide whether a finding is valid. Start with:

- Generic SARIF input
- Observed Polaris SAST/SCA export formats
- Declarative CSV/JSON field mapping

Polaris MCP is useful as a read-only retrieval adapter. The documented Issue
Management MCP tools cannot update Polaris, so comments or triage changes require a
separate supported write path and explicit approval.

## Runtime boundary

Every target supplies a small runtime profile describing how to start, stop, and
health-check the disposable application. Probes are scoped to its approved base URL
and use test accounts or synthetic data. Runtime evidence proves only what was
exercised in that particular deployment.

## Agent loop

For each finding, the controller asks for the least costly evidence that can change
the verdict:

1. Verify the source and dependency snapshot.
2. Check whether the file/component belongs to the deployed boundary.
3. Trace the relevant source path and security control.
4. Run a safe runtime probe when it can materially reduce uncertainty.
5. Stop with `Needs review` when the remaining test is unsafe or unauthorized.

The model proposes and interprets evidence. Deterministic code handles parsing,
hashing, schema checks, redaction rules, deduplication, and output generation.
