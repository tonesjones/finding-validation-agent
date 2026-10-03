# Operations guide

This guide is for people who run the Finding Validation Agent (fva) and tune its AI models. It holds the
operator detail: how scoring works, how each finding is routed to a model tier, and which command-line options
change a run. For what the tool is and why it exists, start with the [README](../README.md).

## Assess options

Source pinning requires Git for a checkout containing `.git`, including worktrees.
If Git is missing or the tracked inventory is unreadable, `assess`, discovery and
evaluation stop rather than walking untracked files. Check Git installation and
repository permissions. A source archive without `.git` can still use file walking.
Pinning disables repository fsmonitor, external diff, textconv and configured
clean/process helpers without writing repository configuration or the index.
Helper-managed content is compared as raw source with CRLF normalization; its
dirty status can differ from the repository's filter-transformed comparison.
Do not mutate the scanned checkout or its Git configuration during pinning.

These options change how `python -m fva assess` runs. Output goes to `data/runs/<timestamp>-<client>/`.

| Option | What it does |
|---|---|
| `--client codex \| claude-code \| anthropic \| local` | Which model client to use. Routing between tiers is on for `codex` only. |
| `--model <name>` | One model for every cluster. Turns routing off. |
| `--no-route` | `codex` only: the senior tier for every cluster. |
| `--astra <id>` | Send the group that holds this scanner finding id to the Astra tier. Repeatable. Needs routing. |
| `--workers N` | Run N model calls in parallel. Default 1. About 4 is a sensible start. Results are the same as a sequential run. |
| `--credential-model skip` | Don't send hard-coded-credential findings to a model. Only a runtime test can decide them. Default is `ask`. Compare both with `fva score` before you switch. |
| `--dry-run` | Write the prompts only. No model calls. |
| `--limit N` | Assess only the first N groups (a smoke test). |
| `--findings`, `--lockfile` | Where the Polaris export and the resolved lockfile are. The defaults point into `data/` (local only). |

## Automatic scoring

`python -m fva score <run_dir> [--key <answer key>]` measures a run without hand review. The default key is the
Juice Shop proof-of-concept ledger (`data/poc-report/final-validation-ledger.jsonl`, 570 findings validated by hand
and at runtime). Code: `fva/export/score.py`.

**How it works.**
1. Build the worksheet rows for the run (same logic as `fva worksheet`).
2. Match each row to the key by Polaris issue id (`source_finding_id` = ledger `candidate_id`). Rows newer than
   the key are reported as `not_in_key` and not scored.
3. Convert the key's classification to a verdict and reason code (`LEGACY_POC_MAP` in `fva/reason_codes.py`),
   for example `test_only` → not applicable / `TEST_ONLY`, `true_positive_runtime_validated` → confirmed.
4. Give each row one outcome:

| Outcome | Meaning |
|---|---|
| `agree` | Same verdict as the key. |
| `agree_static` | Key says confirmed (proven at runtime), fva says likely. The best fva can do without runtime tests, so it counts as agreement. |
| `unresolved` | fva says needs review. Not wrong, but a person still has to look. |
| `incorrect_demotion` | Key says real or open, fva cleared it (not applicable or not security). **The dangerous error; the target is 0.** |
| `over_flag` | Key cleared it, fva says likely or confirmed. Costs review time, not safety. |
| `wrong_clearance_kind` | Both cleared it, but one says not applicable and the other not security. |
| `other_mismatch` | Any other disagreement. |

5. Compute the metrics:
   - **Agreement**: (agree + agree_static) / scored rows. **Strict agreement**: agree only.
   - **Incorrect demotions**: count, each listed in the report.
   - **Unresolved rate**: needs review / scored rows.
   - **Queue reduction**: share of all findings a person no longer has to triage (not needs review, likely or confirmed).
   - **Reason code match**: of agreeing rows, how many also have the key's reason (e.g. both say `TEST_ONLY`).
   - Breakdowns by answer-key verdict (confusion table), scanner (SAST/SCA/DAST) and tier (`rules` when no model
     was called, `junior`, `senior`, `astra`), so Luna and Sol can be compared.

**Output** in the run folder: `score.md` (readable report, with incorrect demotions listed first to check),
`score.json` (all numbers, for comparing runs), `score_rows.csv` (every row with key verdict, fva verdict, tier and
outcome, sorted by outcome).

**Limits.** The key is one app (Juice Shop) validated by one PoC. Runtime-only verdicts (an active credential, an
exploited advisory) can only reach `agree_static` or `unresolved` until runtime probes exist. A different app needs
its own key in the same format (`candidate_id`, `classification`).

## Which AI model handles each finding

The tool sends each group of findings (findings on the same code line or advisory) to one of
three model tiers. Fixed rules in code pick the tier, not a model (`fva/reasoning/routing.py`, `route()`).
The first matching rule wins, and if any finding in a group needs the senior tier, the whole group goes there.

| # | Rule | Tier |
|---|---|---|
| 1 | The scanner finding id was passed with `--astra <id>` | Astra |
| 2 | Any finding is **critical** severity | Senior |
| 3 | It is an **SCA** (open-source package) finding | Senior |
| 4 | CWE is security-sensitive: injection and code execution (78, 79, 89, 94, 95, 676, 943), SSRF (918), authentication / authorization / JWT (284, 285, 287, 345, 347, 613, 639, 862, 863), crypto (320, 326, 327) | Senior |
| 5 | CWE is bounded: dead code / no effect / unused value (398, 561, 563), hard-coded credentials (259, 321, 522, 547, 798) | Junior |
| 6 | **High** severity with a CWE in neither list | Senior |
| 7 | Everything else (low or medium severity, non-injection) | Junior |

**Escalation.** A junior answer is re-asked once on the senior tier (no further retries, never to Astra) when:
the output can't be parsed; a cited code quote isn't in the source; the answer argues both ways; the model reports
low confidence (except hard-coded credentials, which only a runtime test can decide); or it argues that a high or
critical finding doesn't apply. Both attempts are kept in `assessments.jsonl`.

**Current model per tier** (`--client codex`, personal Codex subscription). Change a tier with its environment
variable, no code change needed:

| Tier | Role | Model today | Variable |
|---|---|---|---|
| Junior | Bulk, clear-cut questions | GPT-6 Luna (`gpt-6-luna`) | `FVA_MODEL_JUNIOR` |
| Senior | Security judgment, escalations | GPT-6 Sol (`gpt-6-sol`) | `FVA_MODEL_SENIOR` |
| Astra | Hard cases, manual flag only | GPT-6 Astra (`gpt-6-astra`) | `FVA_MODEL_ASTRA` |

`--no-route` sends everything to the senior tier; `--model <name>` uses one model for everything. To keep
hard-coded-credential findings away from every model, use `--credential-model skip` (see "Assess options").

**Remapping for the company LiteLLM gateway (planned, not built).** The gateway client will use the same tiers
and variables, set to the gateway's model aliases. Known on the gateway: GPT-5.6 Luna and GPT-5.6 Sol
(GPT-6 not confirmed yet); Claude Opus / Sonnet / Haiku are alternatives. Re-run the routed comparison against
the PoC answer key after remapping, because results for one model family don't carry over to another.
See [CHECKPOINT.md](../CHECKPOINT.md), "Work laptop: LiteLLM gateway".
