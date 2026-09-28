# Finding Validation Agent

Validates SAST/SCA scanner findings (Polaris today) against source code, dependency
inventory, and a live runtime, and records evidence-backed verdicts. Start every session by
reading `CHECKPOINT.md` (status, decisions, next steps) and update it when status changes.

## Run

```powershell
pip install -e .                      # once (needs pydantic)
python -m pytest                      # all tests; private-data tests skip when data/ is absent
$env:FVA_JUICESHOP_SRC = "C:\TestCode\Juiceshop 20.2.0"   # enables the Juice Shop source tests

# Evidence + model assessment for the Juice Shop reference case
python -m fva assess --client codex --source "C:\TestCode\Juiceshop 20.2.0" --limit 1   # smoke test
python -m fva assess --client codex --source "C:\TestCode\Juiceshop 20.2.0"             # full run (Luna/Sol routing)
python -m fva assess --client codex --no-route --source "C:\TestCode\Juiceshop 20.2.0"  # GPT-6 Sol for every cluster
python -m fva assess --dry-run --source "C:\TestCode\Juiceshop 20.2.0"                  # prompts only

# Polaris (read-only MCP). Token: $env:POLARIS_ACCESS_TOKEN or data\.polaris-token
python -m fva.polaris_mcp export --project <projectId> --branch <branchId>   # ids: data/LOCAL-NOTES.md
```

Roles: you (Claude) act as VP of engineering and own final review; Codex does the assessment work with
GPT-6 Luna (junior, bulk) and GPT-6 Sol (senior, security-sensitive judgment), routed per cluster by
default (about 42-44% of Sol-only cost at list prices). Routing policy and results: `CHECKPOINT.md`.

Clients: `--client codex | claude-code | anthropic | local`; `--model` passes a model name through.
Runs write to `data/runs/<timestamp>-<client>/` (`summary.json`, `assessments.jsonl`, `evidence.jsonl`).
Model answers are cached in `data/cache/model/`; CLI failures log to `data/logs/`.

## Rules (non-negotiable)

- **Never commit `data/`.** It holds real Polaris exports, the PoC ledger, lockfiles, tokens, run output.
  Raw Polaris responses contain internal service URLs and the tenant id. Commit only sanitized fixtures
  under `tests/fixtures/`, and check them for real ids before committing.
- **Never print or log tokens.** Polaris access is read-only; only the tools in `READ_ONLY_TOOLS`.
- **The model never confirms.** `confirmed` needs runtime, negative-control, human-review or imported
  evidence (enforced in `fva/invariants.py`). Model and static evidence can only argue, cite, or refute.
- **Only redacted code goes to a model** (`fva/redact.py`), and every model citation is verified against the
  pinned source before it is kept (`fva/reasoning/assessor.py`).
- **Runtime probing (not built yet):** build the target allowlist and human-approval gate first, prove with
  tests that out-of-allowlist targets and non-GET verbs are rejected, then add probes. No destructive or DoS tests.
- Preserve scanner ids byte-for-byte. Reason codes are a closed, append-only vocabulary (`fva/reason_codes.py`).
- Polaris is the only SAST engine for this project (no Semgrep/CodeQL).

## Layout

`fva/schemas.py` data model · `fva/adapters/` scanner input (SARIF, Polaris flat + MCP, mapping, PoC ledger) ·
`fva/correlation/` source pin, locate, dependency, reachability · `fva/reasoning/` model clients + assessor ·
`fva/pipeline.py` batch run · `fva/langpacks/` per-language rules (Node today) · `fva/polaris_mcp.py` Polaris client.

## Reference data (local only)

- Juice Shop 20.2.0 source: `C:\TestCode\Juiceshop 20.2.0` (local import commit `15b4641`; upstream `1618a611`)
- PoC answer key: `data/poc-report/final-validation-ledger.jsonl` (570 rows) + `runtime-validation-summary.json`
- Live Polaris export: `data/polaris-export/` (573 issues + `types.json`)
- Resolved npm lockfile: `data/resolved/juiceshop-20.2.0-package-lock-resolved-2026-09-27.json`
- Black Duck product docs corpus: `C:\TestCode\Product Docs`

## Git

Work on a branch, open a PR into `main`, keep `CHECKPOINT.md` current. Line endings: commit with
`core.autocrlf=input`; README/ROADMAP/docs show phantom CRLF-only changes on Windows, don't commit those.
