# Finding Validation Agent

An evidence-driven agent for validating commercial SAST and SCA findings against
the application source, its resolved dependencies, and an authorized disposable
runtime.

## The idea

Commercial scanners are good at finding candidates, but their results often mix
deployed vulnerabilities with test code, inactive configuration, stale package
versions, and findings that need application context. This project tests whether
an AI agent can add that missing context without hiding uncertainty.

The agent does not replace a scanner. It consumes scanner results, preserves every
original finding, gathers independent evidence, and produces an auditable verdict.

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

- Polaris SAST and SCA exports
- SARIF 2.1.0 from other scanners
- A small documented CSV/JSON mapping for tools without SARIF
- Source checkout and build/dependency metadata
- An authorized local URL or command for the disposable runtime

Outputs:

- Canonical JSONL finding ledger
- Evidence receipts with secrets removed
- Human-readable experiment report
- Enriched SAST or SCA SARIF suitable for Polaris External Analysis
- Optional comment/triage preview; platform writes remain approval-gated

## First case study

The first experiment used OWASP Juice Shop 20.2.0 and 570 Polaris findings. Source
and runtime analysis separated confirmed/current security findings, unresolved safe-
testing cases, valid non-security observations, and findings not relevant to that
specific deployment. See [Experiment 001](docs/experiments/001-juice-shop.md).

## Current status

The Juice Shop proof of concept is complete. The next milestone is to extract its
normalization, evidence-ledger, validation, and SARIF-enrichment steps into a small
vendor-neutral command-line agent. See [ROADMAP.md](ROADMAP.md).

## Project principles

- Preserve original finding identifiers and raw evidence provenance.
- Never force a binary verdict when evidence is insufficient.
- Treat runtime observations as deployment-specific, not universal proof.
- Keep SAST, SCA, and newly discovered findings separate in measurements.
- Never run destructive, denial-of-service, or out-of-scope tests automatically.
- Keep credentials, proprietary exports, and sensitive source out of this repository.

This is a research project, not a claim of complete vulnerability detection or an
automatic replacement for human security review.
