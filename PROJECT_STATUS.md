# Project status

Last updated: 2026-10-01

## Goal

Validate Polaris SAST, SCA, and DAST findings with source and runtime evidence, and
turn them into one prioritized, evidence-backed issue per real flaw. See the
[README](README.md#end-result).

## Current

- Intake (SARIF, Polaris export, Polaris MCP, field mapping), source pinning,
  location, dependency reconciliation, and reachability are implemented in `fva/`.
- The product team is expected to build cross-scanner correlation; this project
  focuses on validation and evidence-based prioritization.

## Next

1. Migrate the repository to a company GitHub account.
2. Confirm data-handling rules before ingesting real Polaris results.
3. Build v0.4: DAST adapter, SAST↔DAST linking, grouped issues, runtime modes.

## Blocked

- Real Polaris ingestion waits on the repository migration.
