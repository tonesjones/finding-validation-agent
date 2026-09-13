# Experiment 001: OWASP Juice Shop 20.2.0

## Question

Can an LLM supplied with commercial SAST/SCA results, the matching source, and a
live disposable application improve the practical accuracy of the scanner queue?

## Target

- Application: OWASP Juice Shop 20.2.0
- Source commit: `1618a611b173b4bf114028e6e02549950606e29d`
- Commercial input: 524 Polaris SAST findings and 46 Polaris SCA findings
- Runtime: isolated local `npm start` deployment

## Method

Every original finding identifier was preserved. Findings were correlated with
source, deployment configuration, resolved dependencies, and safe live probes.
Potential crash, hang, or denial-of-service tests were not executed merely to force
a verdict.

## Result

| Deployment-aware category | Count | Share |
|---|---:|---:|
| Confirmed/current security | 56 | 9.8% |
| Reachable or likely; safe deeper test needed | 12 | 2.1% |
| Valid non-security quality | 42 | 7.4% |
| Not relevant to the tested runtime | 460 | 80.7% |

The result measures actionable-security precision for this deployment. It does not
mean 460 scanner records were necessarily technically incorrect.

Live evidence confirmed examples including SQL injection, NoSQL injection, SSRF,
JWT authorization bypass, stored XSS, active hard-coded credentials, session reuse,
server-side evaluation, and an uncapped upload path. Negative controls and runtime
configuration demoted findings whose prerequisites were absent.

## Important lessons

- Source scope removed test files, teaching fixtures, specifications, and unused
  infrastructure from the live security queue.
- Runtime testing distinguished callable code from behavior actually exercised in
  the deployment.
- SCA decisions require the resolved dependency snapshot; this target had no usable
  lockfile and fresh installation introduced version drift.
- A live negative result does not prove every untested path is unreachable.
- Scanner-gap discovery must be measured separately from validation of scanner input.

## Output lesson

Minimal SARIF imported into Polaris as generic Medium issues. Enriched SARIF 2.1.0
needed stable rule identifiers and fingerprints, relative locations, severity/risk,
CWE/category metadata, rule descriptions, exact snippets, and surrounding context to
render useful issue types and Contributing Code Events.

## Limitations

- Juice Shop is intentionally vulnerable and may exist in model training data.
- One local runtime does not represent every deployment configuration.
- Twelve SCA records remained unresolved because safe evidence was insufficient.
- Independent human adjudication is required before claiming general accuracy.
