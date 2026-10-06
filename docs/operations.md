# Operations guide

Use this guide to run FVA, inspect outputs and configure model routing.
It explains the pipeline, scoring and command-line options.
For what the tool is and why it exists, start with the [README](../README.md).

## Source pinning needs Git and never runs repository helpers

`assess` pins the source checkout before it reads it.
`fva/correlation/source_pin.py` hashes the tracked files and records `HEAD` and a
dirty flag.

- A checkout that contains `.git`, including a worktree, needs Git. If Git is missing
  or cannot list the tracked files, the command stops. It does not fall back to
  walking the directory, because that would hash untracked files. Check that Git is
  installed and that you can read the repository.
- A source archive without `.git` is pinned by walking its files.
- Pinning turns off the repository's fsmonitor, external diff, textconv, and clean
  and process filters. It writes neither Git configuration nor the index. Files that
  a filter manages are compared as raw source with CRLF normalized, so the dirty flag
  can differ from what `git status` reports.
- Pinning never enters submodules. Their contents are not in the source hash, and the
  dirty flag ignores every submodule change, including a submodule moved to another
  commit. To include a submodule's source, pin its checkout separately.

Don't change the checkout or its Git configuration while a pin runs.

## How a run works

```
Polaris export -> assess -> triage -> report
                 evidence  decisions  ranked open issues
```

**0. Export.** `python -m fva.polaris_mcp export --project <projectId> --branch <branchId>` saves the Polaris
findings to `data/polaris-export/`. It uses the read-only Polaris MCP server, so it can't change anything in Polaris.
The access token comes from `POLARIS_ACCESS_TOKEN` or from `data/.polaris-token`.

**1. Assess.** `python -m fva assess --client codex --source <checkout> --profile-file <profile.json>` writes to `data/runs/<timestamp>-<client>/`.
See [Assess options](#assess-options). The steps follow.

1. Load Polaris SAST and SCA findings and record the scanner mix.
   `load_findings` accepts saved Polaris MCP JSON pages or one flat Polaris `.jsonl` or `.csv` file.
   Flat records use the mapping in `fva/adapters/polaris.py`. `assess` does not load SARIF or other scanner formats.
   DAST is parked as optional evidence. Without DAST, runtime mode is `none` for static evidence only.
2. Pin the supplied source checkout and record its content hash. You must supply the source that matches the scan.
3. Check the deployment boundary. Findings in test code, sample files, unused deploy config or docs are set aside
   with a rule-based reason. No model is called for them. Each one keeps a `deployment_boundary` evidence record
   that names the rule, so every closure can be checked.
4. Locate each remaining finding at its file and line. For SCA, compare the scanned package version with the
   installed one in the lockfile. A version that isn't installed is set aside too, with a `dependency_resolution`
   evidence record.
5. Check static reachability from the app's entrypoints and package imports in shipped code.
6. Link and group related findings using package imports at SAST sites.
   Optional DAST evidence can link to SAST routes. Every original finding is kept.
7. Assess remaining clusters with a model. Findings at the same sink or advisory share a cluster.
   Routing can escalate a cluster to another tier. See [model routing](#which-ai-model-handles-each-finding).
   Only redacted code is sent. The
   tool checks every quoted line against the real source and drops it if it doesn't match.

Files: `findings.jsonl` (every finding, its disposition and issue), `evidence.jsonl`, `assessments.jsonl`,
`groups.jsonl`, `links.jsonl`, `summary.json`.

**Optional worksheet.** `python -m fva worksheet <run_dir>` writes one suggested verdict per Polaris issue id to
`worksheet.csv` (Excel) and `worksheet.html` (grouped by issue). Every suggestion passes the verdict rules in
`fva/invariants.py`, rule closures included, because each one cites its rule record. A model argument alone never
clears or promotes a finding. A model refutation alone stays `needs_review`.
A `likely` verdict also needs rule evidence. Nothing is written to Polaris.

**2. Triage.** `python -m fva triage <run_dir>` writes `triage.jsonl` and `triage.md`.
`auto` means the verdict passes the evidence and confidence checks.
`review` means the finding stays open. It does not require routine human review or worksheet re-import.
The report keeps a closure open if triage cannot accept it automatically.

**Optional scoring.** `python -m fva score <run_dir>` compares the run with an answer key.
You do not need an answer key to assess an app or produce its report.
See [Automatic scoring](#automatic-scoring).

**Report.** `python -m fva report <run_dir>` writes ranked open issues to `tickets.jsonl`, a text summary to
`report.md`, and a self-contained `report.html`. The HTML page shows the raw finding count, issue counts for
closures, fix tickets and findings that stay open, closures by reason code with cited evidence metadata, and every original Polaris
ID in its grouped issue. Every open ticket has `missing_evidence`. It uses inline CSS and makes no external requests. Evidence summaries, receipt details
and run summary fields other than the profile id are excluded.

**SARIF export.** `python -m fva sarif <run_dir>` writes `sast.sarif` and `sca.sarif`, plus `dast.sarif` only
when the run has DAST findings (SARIF 2.1.0, one result per original finding, never merged). The scanner finding id
is written to `guid`, so `fva.adapters.sarif` reads it back unchanged. `properties.fva` holds the verdict, route, reason codes, issue id and evidence metadata.
A closure triage did not auto-route shows as `needs_review`.
Evidence metadata includes id, type, stance and method. Summaries and receipt content are excluded. Polaris import of these files is unverified.

**Polaris preview.** `python -m fva preview <run_dir>` writes `preview.jsonl` and `preview.md`. Each row covers one
original finding with the current Polaris triage status and severity (when the run recorded them), the suggested
values from `fva/export/polaris_triage_map.py`, an `action` and `approved: false`. Only auto-routed rows can
propose a change. Review rows stay open. Change rows carry the comment a future writer would post (verdict, reason
codes, issue id and evidence id/type/stance/method). It excludes summaries and receipt content. The label map is ASSUMED. This
is a dry run. Nothing is written to Polaris. `approved` stays false.
Polaris write-back is later work, not a routine review step.

## Assess options

These options change how `python -m fva assess` runs. Output goes to `data/runs/<timestamp>-<client>/`.

| Option | What it does |
|---|---|
| `--client codex \| claude-code \| anthropic \| local` | Which model client to use. Routing between tiers is on for `codex` only. |
| `--profile-file <json>` | Required deployment profile. See [Deployment profile](../README.md#deployment-profile) and the Juice Shop example. |
| `--model <name>` | One model for every cluster. Turns routing off. |
| `--no-route` | `codex` only: the senior tier for every cluster. |
| `--astra <id>` | Send the group that holds this scanner finding id to the Astra tier. Repeatable. Needs routing. |
| `--workers N` | Run N model calls in parallel. Default 1. About 4 is a sensible start. Results are written in cluster order. |
| `--credential-model skip` | Don't send hard-coded-credential findings to a model. Only a runtime test can decide them. Default is `ask`. Compare both with `fva score` before you switch. |
| `--prices <json>` | Per-1M-token prices by reported model name, as `{"gpt-6-sol": {"input": 2.0, "cached_input": 0.2, "output": 10.0}}`. Overrides the built-in table in `fva/reasoning/pricing.py`. `summary.json` gets a `cost` block per tier and in total. Only fresh calls count toward `usd`. |
| `--dry-run` | Write the prompts only. No model calls. |
| `--limit N` | Assess only the first N groups (a smoke test). |
| `--findings` | Polaris MCP JSON glob or one flat Polaris `.jsonl` or `.csv` file. Default `data/polaris-export/page-*.json`. |
| `--source` | Required matching source checkout. Missing SAST paths produce a warning. |
| `--out` | Output directory. Default `data/runs/<timestamp>-<client>`. |
| `--cache` | Model-answer cache. Default `data/cache/model`. |
| `--lockfile` | Optional resolved lockfile for dependency version checks. No default. A missing supplied path produces a warning. |

## Automatic scoring

`python -m fva score <run_dir> [--key <answer key>]` measures a run without hand review. The default key is the
Juice Shop proof-of-concept ledger (`data/poc-report/final-validation-ledger.jsonl`, 570 findings).
The key is LLM-driven and includes reported runtime evidence. It needs independent adjudication.
The scoring code is `fva/export/score.py`.

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
| `agree_static` | Key says confirmed (proven at runtime), fva says likely. The best fva can do without supporting runtime evidence, so it counts as agreement. |
| `unresolved` | fva says `needs_review`. The finding stays open until evidence can decide it. |
| `incorrect_demotion` | Key says real or open, fva cleared it (not applicable or not security). **The safety target is 0.** |
| `over_flag` | Key cleared it, fva says likely or confirmed. Keeps a cleared finding open. |
| `wrong_clearance_kind` | Both cleared it, but one says not applicable and the other not security. |
| `other_mismatch` | Any other disagreement. |

5. Compute the metrics:
   - **Agreement**: (agree + agree_static) / scored rows. **Strict agreement**: agree only.
   - **Incorrect demotions**: count, each listed in the report.
   - **Unresolved rate**: needs review / scored rows.
   - **Queue reduction**: share of all findings cleared by the suggested verdict (not needs review, likely or confirmed).
   - **Reason code match**: of agreeing rows, how many also have the key's reason (e.g. both say `TEST_ONLY`).
   - Breakdowns by answer-key verdict (confusion table), scanner (SAST/SCA/DAST) and tier (`rules` when no model
     was called, `junior`, `senior`, `astra`), so Luna and Sol can be compared.

**Output** in the run folder: `score.md` (readable report, with incorrect demotions listed first to check),
`score.json` (all numbers, for comparing runs), `score_rows.csv` (every row with key verdict, fva verdict, tier and
outcome, sorted by outcome).

**Limits.** The key covers one app (Juice Shop) and is not independently adjudicated.
Without supporting runtime evidence, runtime-only verdicts can only reach `agree_static` or `unresolved`. A different app needs
its own key in the same format (`candidate_id`, `classification`).

## Which AI model handles each finding

The tool sends each group of findings (findings on the same code line or advisory) to one of
three model tiers. Fixed rules in code pick the tier, not a model (`fva/reasoning/routing.py`, `route()`).
The first matching rule wins. Except for an explicit Astra selection, any senior-tier finding sends the whole group to senior.

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
low confidence (except hard-coded credentials, which only a runtime test can decide); it argues that a high or
critical finding doesn't apply; or it supports the finding. A model `supports` can make a finding `likely` and route
it automatically, so no `likely` rests on a junior answer alone. Both attempts are kept in `assessments.jsonl`.

**Current model per tier** (`--client codex`, personal Codex subscription). Change a tier with its environment
variable, no code change needed:

| Tier | Role | Model today | Variable |
|---|---|---|---|
| Junior | Bulk, clear-cut questions | GPT-6 Luna (`gpt-6-luna`) | `FVA_MODEL_JUNIOR` |
| Senior | Security judgment, escalations | GPT-6 Sol (`gpt-6-sol`) | `FVA_MODEL_SENIOR` |
| Astra | Hard cases, manual flag only | GPT-6 Astra (`gpt-6-astra`) | `FVA_MODEL_ASTRA` |

`--no-route` sends everything to the senior tier. `--model <name>` uses one model for everything. To keep
hard-coded-credential findings away from every model, use `--credential-model skip` (see "Assess options").

A company LiteLLM client is later work. It is not built.
The current client decision is recorded in [STATUS.md](../STATUS.md).

## Decisions from validation evidence

Hand-built `runtime_probe` and `advisory_precondition` records do not automatically
confirm or close findings. They stay `needs_review` until an FVA collector/importer
establishes their provenance. Changing an agent's source interpretation to a rule
evidence type does not make it independent rule evidence.

Worksheet runtime evidence must match the profile in the run's `summary.json`.
Missing or mismatched profiles keep the finding unresolved. Evidence cannot select its
own expected deployment. A directly constructed `RUNTIME_CONFIRMED` verdict must
cite a supporting runtime probe and a neutral `negative_control` whose
`tool_versions.control_for` names that probe's evidence ID. Both must cover the
finding and match the verdict's deployment. A control alone cannot confirm.
Historical imported assessments preserve their original decision; they do not
prove that FVA ran a new probe with a control.

Keep evidence for different deployments in separate runs with distinct profiles.
A reproduction on local Node does not confirm a hosted deployment. A failed
probe does not establish non-applicability. Verify deployment identity before deciding
applicability for a hosted target.

## Approved localhost runtime collection

This collector exists but is parked. It is separate from the normal SAST and SCA pipeline.

`python -m fva runtime` collects and imports a small approved GET plan.
`execution_marker` supports assessable SAST CWE-94 findings.
`header_disclosure` supports assessable SAST CWE-200 and CWE-201 findings.
`sca_marker` needs an assessable SCA finding and a cited advisory call site.
The latter two also need a pinned `source_root`. See `ProbePair` and `Plan` in `fva/runtime.py`.
The collector does not generate exploits. Other cases remain unresolved.

An operator approves the entire plan once, including the mapping from each finding
to its probe, control and expected marker. The plan's rationale must explain why
the marker establishes execution at the reported sink, rather than ordinary
reflection or an intended response. A matching marker is meaningful only for that
approved test. There is no per-response grading step.

Keep the plan, approval, raw responses and derived run in ignored `data/`. A plan
has these fields:

```json
{
  "profile_id": "local-validation",
  "source_content_sha256": "<64-character source tree hash from summary.json>",
  "findings_sha256": "<SHA-256 of the exact findings.jsonl bytes>",
  "allowed_urls": [
    "http://127.0.0.1:3000/control",
    "http://127.0.0.1:3000/probe"
  ],
  "pairs": [{
    "finding_id": "<existing SAST CWE-94 finding ID>",
    "probe": {"method": "GET", "url": "http://127.0.0.1:3000/probe"},
    "control": {"method": "GET", "url": "http://127.0.0.1:3000/control"},
    "marker": "UNIQUE_EXECUTION_MARKER_12345",
    "rationale": "Explain the harmless computation and its connection to the reported sink."
  }]
}
```

These example routes describe the format, not a working exploit. The expected
marker must be absent from both requests after case-insensitive inspection,
repeated URL decoding and base64/hex decoding of path segments and query values,
and from the control
response. Choose a benign probe that computes the marker without changing data.
Both responses must be complete HTTP 200 responses and carry
`X-FVA-Source-SHA256` equal to the pinned source tree hash. Add this identity header
when starting your controlled local app. It is a declaration by that app, not
cryptographic proof of the running binary or remote attestation.

1. Prepare the exact plan against an existing run. Compute the findings file hash
   and use the profile and source hash from its `summary.json`.
2. In your interactive terminal, run
   `python -m fva runtime approve data/plan.json --out data/approval.json`.
   It displays the complete plan and requires your name and the first 12 characters
   of its hash before writing approval. Redirected input is rejected. This sends
   no requests. The agent must not run this command or fabricate its receipt on
   behalf of the operator. `approval-template` remains available for a pending
   receipt, which cannot authorize collection. Legacy manually marked receipts
   are rejected. Approval timestamps must include a timezone and precede collection.
3. Run `python -m fva runtime collect data/runs/base --source <checkout> --plan data/plan.json --approval data/approval.json --out data/collection`.
4. Run `python -m fva runtime import data/runs/base data/collection --out data/runs/runtime-derived`.
   Import sends no requests. It copies the base findings, evidence and summary
   into a new directory and writes the receipt and worksheet there.

Collection accepts only explicit loopback IP addresses with a port, on one origin,
and exact allowlisted URLs. Hostnames and hosted targets are rejected. All requests
are GET, without credentials, environment proxies, cookies or redirect following.
A plan has at most eight pairs. Each connection has a three-second socket timeout;
after connecting, all request/response I/O has a three-second deadline. Each body
is capped at 64 KiB. Transport failures and truncated or unexpected responses
remain neutral evidence, never automatic dismissals.

The collector checks source content before and after probing. Import verifies the
approved plan, profile, source and exact findings file, then recomputes evidence
from the retained response bytes. Worksheets repeat that verification and require
the stored evidence to match exactly before promoting a runtime finding. Merely
writing the collector's method name into an evidence record grants no trust.
Receipt hashes bind artifacts and detect inconsistent edits; they are not
signatures. A person able to rewrite both the local approval and collection is
inside the trust boundary. Output directories must be new, so base runs and old
collections are preserved.

The interactive-terminal requirement prevents ordinary noninteractive approval;
it does not authenticate a human against a process that can create a terminal or
rewrite local artifacts. The local operator and artifact store remain trusted.
The encoding checks reject common reflection cases, not every possible application
transformation. Review the finding-specific oracle before approving the plan.

Each derived run supports one collection. Importing onto an already derived run
is rejected; start each collection from the original base run. Invalid or missing
receipts produce a warning in the worksheet command summary and HTML worksheet.
Receipts contain raw, unredacted response bodies. Keep them in ignored `data/`;
never send them to a model, attach them to tickets, or publish them. Only sanitized
evidence summaries are suitable for those uses.
