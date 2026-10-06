# Finding Validation Agent

FVA checks a Polaris SAST and SCA export against the matching source checkout.
It closes findings it can prove do not apply, with a cited reason.
It ranks the rest in an open report that says what evidence is missing.
This is a working prototype. Start every session by reading STATUS.md.
There is no routine human review. DAST is parked as optional evidence.

## Run

Follow the [README quick start](README.md#quick-start) for setup and a deployment profile.

```bash
python -m fva assess --findings "<export>/page-*.json" --source "<checkout>" --profile-file "<profile.json>" --out runs/app --cache runs/cache
python -m fva triage runs/app
python -m fva report runs/app
```

`--profile-file` is required. `--lockfile` is optional and has no default.
`assess` accepts Polaris MCP exports or one flat Polaris `.jsonl` or `.csv` file.
The default `codex` client routes model calls between GPT-6 Luna and GPT-6 Sol.
`--model` or `--no-route` disables tier routing.
See [docs/operations.md](docs/operations.md) for commands, outputs and scoring.

## Rules (non-negotiable)

- **This repo is public on GitHub.** Commit only this repo's own work. Never commit Polaris data, secrets,
  tenant ids, internal URLs or content copied from other repos or local folders.
- **Never commit `data/`.** It holds real Polaris exports, the PoC ledger, lockfiles, tokens, run output.
  Raw Polaris responses contain internal service URLs and the tenant id. Commit only sanitized fixtures
  under `tests/fixtures/`, and check them for real ids before committing.
- **Never print or log tokens.** Polaris access is read-only. Use only the tools in `READ_ONLY_TOOLS`.
- **`likely` is not `confirmed`.** It needs rule-derived static evidence. Model output alone is insufficient.
- **The model never confirms.** `confirmed` needs supporting runtime, DAST or imported
  evidence. `fva/invariants.py` also retains the historical `human_review` evidence type.
  There is no routine review step or review importer. Model and static evidence cannot confirm.
- **Only redacted code goes to a model** (`fva/redact.py`), and every model citation is verified against the
  pinned source before it is kept (`fva/reasoning/assessor.py`).
- **Runtime probing:** `runtime` accepts only an approved exact localhost GET plan.
  Keep approval and allowlist gates tested before expanding probes. Never fabricate
  operator approval or run `runtime approve` on the operator's behalf, including
  through an agent-created TTY. Raw receipts must never go to models or tickets.
  No destructive or DoS tests. Hosted probing is not supported.
- Preserve scanner ids byte-for-byte. Reason codes are a closed, append-only vocabulary (`fva/reason_codes.py`).
- Polaris is the only scanner input for this project.

## Gotchas

- Pipe `< /dev/null` into a background `codex exec`, or it hangs waiting on stdin.
- Adding reason codes changes the assess prompt and empties the model cache, unless the new codes
  are left out of `MODEL_CODES` in `fva/reasoning/assessor.py`.
- The pipeline writes run files in text mode, so their hashes differ between Windows and Linux.
  Don't pin run-file hashes in tests.
- Python `write_text` on Windows writes CRLF. Normalize touched files to LF before committing.
- Stacked PRs: don't run `gh pr merge --delete-branch` on a PR that others are based on, because
  deleting the base branch closes them. After squash-merging the base, rebase the stacked branch
  onto `main` (`git rebase --onto origin/main <old-base> <branch>`) or it will conflict.

## Layout

- `fva/schemas.py` defines records and deployment profiles.
- `fva/adapters/polaris.py` loads Polaris exports and flat records.
- `fva/correlation/` pins source and collects static evidence.
- `fva/reasoning/` runs model clients and verifies citations.
- `fva/verdicts.py` suggests verdicts from evidence.
- `fva/triage.py` decides which verdicts stand automatically.
- `fva/export/` writes worksheets, scores, reports, SARIF and previews.
- `fva/pipeline.py` runs batch assessment.
- `fva/langpacks/` contains Node rules.
- `fva/polaris_mcp.py` retrieves Polaris data through read-only tools.

## Git

Work on a branch, open a PR into `main`, keep `STATUS.md` current. Line endings are normalized by
`.gitattributes` (`* text=auto`). CI (`.github/workflows/tests.yml`) runs pytest on Linux and Windows.
