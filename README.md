# Finding Validation Agent

An evidence-driven agent for validating commercial SAST, SCA, and DAST findings
against the application source, its resolved dependencies, and authorized runtime
evidence.

## The idea

Commercial scanners are good at finding candidates, but their results often mix
deployed vulnerabilities with test code, inactive configuration, stale package
versions, and findings that need application context. This project tests whether
an AI agent can add that missing context without hiding uncertainty.

The agent does not replace a scanner. It consumes scanner results, preserves every
original finding, gathers independent evidence, and produces an auditable verdict.

Cross-scanner *correlation* answers "which SAST, SCA, and DAST findings are the same
flaw?" This project goes one step further and answers "is that flaw real in *this*
deployment, and what is the evidence?" Correlation shrinks duplicates; validation
shrinks the queue.

## End result

For one build of an application, the finished agent will:

1. **Import** Polaris SAST, SCA, and DAST results, pinned to the exact source commit
   and dependency snapshot the scans used.
2. **Group** findings that describe the same flaw into one issue — for example a SAST
   SQL-injection sink in `routes/search.ts`, the DAST hit on
   `/rest/products/search?q=`, and an SCA advisory on the package involved.
3. **Validate** each issue with independent evidence:
   - Is the code reachable from a deployed route or entry point?
   - Is it test code, inactive configuration, or a package that never ships?
   - Is the vulnerable dependency function actually called?
   - Did an authorized DAST scan observe it at runtime?
4. **Decide** a verdict (below) with evidence receipts, confidence, and open questions.
5. **Rank and route** issues into remediation queues, and export enriched SARIF back
   to Polaris.

## How this helps the security team

- **A smaller queue.** Findings outside the deployed boundary or without security
  impact are closed with documented evidence instead of re-triaged every scan.
- **Priority by evidence, not just scanner severity.** "Confirmed + reachable + seen
  by DAST" comes first; a critical advisory in a never-called package drops.
- **One fix, many findings.** A grouped issue becomes one ticket with the file, line,
  route, and DAST request together; fixing it clears every linked finding.
- **Fix location included.** Each ticket names the sink or dependency upgrade and why
  it matters.
- **Auditable closures.** Every "Not applicable" carries receipts a reviewer or
  auditor can check.
- **Gaps stay visible.** "Needs review" states exactly what is missing (for example,
  "DAST did not cover this route"). Missing evidence never makes a finding look safe.

## What the agent should do

1. Import SAST or SCA findings through a format adapter.
2. Pin the exact source revision and dependency snapshot used by the scan.
3. Correlate each finding with source, configuration, and deployment boundaries.
4. Exercise only authorized, safe runtime paths in a disposable environment.
5. Classify each finding with evidence, confidence, and unresolved questions.
6. Export a vendor-neutral evidence ledger and enriched SARIF 2.1.0.
7. Optionally run a separate discovery pass for issues the commercial tools missed.

## Verdict model

- **Confirmed:** Evidence supports a security-relevant issue in the tested deployment.
- **Not applicable:** The finding does not apply to the tested source or runtime.
- **Valid non-security:** The code observation is real but is quality or reliability related.
- **Needs review:** Evidence is incomplete, conflicting, unsafe to obtain, or configuration dependent.

“Not applicable” is intentionally different from “scanner false positive.” A scanner
may correctly identify syntax that is outside the deployed application boundary.

## Inputs and outputs

Initial inputs:

- Polaris SAST, SCA, and DAST exports
- SARIF 2.1.0 from other scanners
- A small documented CSV/JSON mapping for tools without SARIF
- Source checkout and build/dependency metadata
- Optional: an authorized local URL or command for a disposable test runtime

Outputs:

- Canonical JSONL finding ledger
- Evidence receipts with secrets removed
- Human-readable experiment report
- Enriched SAST or SCA SARIF suitable for Polaris External Analysis
- Optional comment/triage preview; platform writes remain approval-gated

## Runtime evidence and consent

Actively probing a customer's running application requires their explicit consent,
so live testing is never the default. Runtime evidence comes from one of three modes:

| Mode | Runtime evidence source | When to use |
| --- | --- | --- |
| `none` | Static evidence only | No runtime data available |
| `dast-evidence` (default) | Findings from a DAST scan the customer already authorized | Normal use |
| `live-localhost` | Safe probes against a disposable local instance | Intentionally vulnerable test apps (e.g. Juice Shop) only |

## First case study

The first experiment used OWASP Juice Shop 20.2.0 and 570 Polaris findings. Source
and runtime analysis separated confirmed/current security findings, unresolved safe-
testing cases, valid non-security observations, and findings not relevant to that
specific deployment. See [Experiment 001](docs/experiments/001-juice-shop.md).

## Current status

The Juice Shop proof of concept is complete, and the intake, source-correlation,
dependency, and reachability layers have been extracted into `fva/`. The next
milestone adds DAST as runtime evidence and groups findings across scanners. Before
any work that ingests real Polaris results, this repository will move to a company
GitHub account. See [ROADMAP.md](ROADMAP.md).

## Project principles

- Preserve original finding identifiers and raw evidence provenance.
- Never force a binary verdict when evidence is insufficient.
- Treat runtime observations as deployment-specific, not universal proof.
- Keep SAST, SCA, and newly discovered findings separate in measurements.
- Never run destructive, denial-of-service, or out-of-scope tests automatically.
- No live runtime testing without explicit authorization; default to existing DAST evidence.
- A missing DAST result is never proof that a finding is safe.
- Keep credentials, proprietary exports, and sensitive source out of this repository.

This is a research project, not a claim of complete vulnerability detection or an
automatic replacement for human security review.
