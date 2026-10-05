# Plan: DAST on the Polaris app "FVA"

The PoC Polaris app had SAST and SCA only, so the DAST stack was frozen (CHECKPOINT, 2026-10-02) with an
assumed envelope in `fva/adapters/polaris.py` (`from_dast_issue`, `load_dast`). The new Polaris app "FVA"
has SAST, SCA and DAST. This plan gets a real DAST export, replaces the assumptions with measured facts, and
measures what DAST evidence adds. Codex does the work (prompt: `dast-fva-codex-prompt.md`); Claude reviews the PR.

## Prerequisite (owner, in the Polaris UI)

- Run a DAST scan for app FVA against a Juice Shop 20.2.0 target you are authorized to scan, and SAST/SCA
  on the same source commit.
- Record the project and branch ids in `data/LOCAL-NOTES.md`, never in git.
- Codex never starts scans, never probes hosted targets, and uses only `READ_ONLY_TOOLS`.

## Items (branch `codex/dast-fva`, one PR)

| # | Item | Acceptance |
|---|------|-----------|
| D0 | Export the FVA app with `python -m fva.polaris_mcp export` into `data/polaris-export-fva/`; run `inventory` to capture DAST tool schemas | Export has DAST issues (`context.toolType == dast`) and `dast-types.json`; nothing under `data/` in git |
| D1 | `fva census` on the new export; document the real DAST envelope (fields, evidence links, location, method, parameter) | `data/analysis/census-fva.md` exists; field names only (no values) summarized in `docs/operations.md` |
| D2 | Reconcile `from_dast_issue` with the real envelope; remove "ASSUMED" where verified | All real DAST issues load; scanner ids byte-identical; hosts dropped; snippets redacted |
| D3 | Sanitized fixture `tests/fixtures/polaris_dast_real_*.json` and tests | No tenant id, internal URLs, hosts or tokens; grep result in the PR body; tests pass on Linux and Windows |
| D4 | Full assess with runtime mode `dast-evidence`, routed, `--workers 4` | Run dir under `data/runs/`; `summary.json` has DAST counts and a cost block |
| D5 | Measure SAST↔DAST link accuracy (roadmap v0.7) by checking high and medium links against source | Link precision per confidence tier recorded in CHECKPOINT; no `confirmed` from model output alone |
| D6 | Compare with baseline `20261004-js-merged`: auto share, agreement, incorrect demotions; run `fva score`, `fva report`, `fva sarif` (`dast.sarif`) | 0 incorrect demotions; deltas recorded in CHECKPOINT and PLAN |

## Invariants

- Never commit `data/`. Never print tokens.
- A DAST no-hit never demotes. Only high-confidence links `support`.
- Reason codes are append-only. DAST confirms only through the existing `DAST_OBSERVED` path in `fva/invariants.py`.

## Stop conditions

Stop and report instead of guessing if the export has zero DAST issues, the envelope can't be mapped
without new reason codes, or a step would need a hosted request or a token in output.

## Review (Claude)

Fixture sanitization grep, CI green on Linux and Windows, CHECKPOINT numbers match `summary.json` and
`score.md`, 0 incorrect demotions, and no `confirmed` without DAST, runtime or human-review evidence.
