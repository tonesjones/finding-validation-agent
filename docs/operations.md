# Operations guide

This guide is for people who run the Finding Validation Agent (fva) and tune its AI models. It holds the
operator detail: what each step of a run does, how scoring works, how each finding is routed to a model tier, which
command-line options change a run. For what the tool is and why it exists, start with the [README](../README.md).

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
0 export -> 1 assess -> 2 worksheet -> 3 score -> report -> fixes
read-only MCP  evidence  CSV + HTML  vs answer key  open issues
```

**0. Export.** `python -m fva.polaris_mcp export --project <projectId> --branch <branchId>` saves the Polaris
findings to `data/polaris-export/`. It uses the read-only Polaris MCP server, so it can't change anything in Polaris.
The access token comes from `POLARIS_ACCESS_TOKEN` or from `data/.polaris-token`.

**1. Assess.** `python -m fva assess --client codex --source <checkout>` writes to `data/runs/<timestamp>-<client>/`.
See [Assess options](#assess-options). The steps:

1. Load the Polaris findings (SAST, SCA, and DAST when the customer has it) and record the scanner mix.
   No DAST (for example a non-web app) means runtime mode `none`: static evidence only.
2. Pin the source: a content hash of the exact files that were scanned.
3. Deployment boundary: findings in test code, sample files, unused deploy config or docs are set aside
   with a rule-based reason. No model is called for them. Each one keeps a `deployment_boundary` evidence record
   that names the rule, so every closure can be checked.
4. Locate each remaining finding at its file and line. For SCA, compare the scanned package version with the
   installed one in the lockfile. A version that isn't installed is set aside too, with a `dependency_resolution`
   evidence record.
5. Static reachability: is the file reachable from the app's entrypoints, and is the package imported by shipped code.
6. Link and group: an SCA package imported in a SAST finding's file, and a DAST hit on a SAST sink's route,
   are merged into one issue. Every original finding is kept.
7. Model assessment: one call per cluster (findings on the same sink or advisory), routed to a model tier (see
   [Which AI model handles each finding](#which-ai-model-handles-each-finding)). Only redacted code is sent. The
   tool checks every quoted line against the real source and drops it if it doesn't match.

Files: `findings.jsonl` (every finding, its disposition and issue), `evidence.jsonl`, `assessments.jsonl`,
`groups.jsonl`, `links.jsonl`, `summary.json`.

**2. Worksheet.** `python -m fva worksheet <run_dir>` writes one suggested verdict per Polaris issue id to
`worksheet.csv` (Excel) and `worksheet.html` (grouped by issue). Every suggestion passes the verdict rules in
`fva/invariants.py`, rule closures included, because each one cites its rule record. A model argument alone never
clears or promotes a finding: "doesn't apply" from the model alone stays needs review, and likely also needs rule
evidence. Nothing is written to Polaris.

A run made before 2026-10-02 has no rule records. The worksheet warns about this and leaves those findings as needs
review until you run `assess` again. That costs nothing, because the model answers come from the cache.

**3. Score.** `python -m fva score <run_dir>`. See [Automatic scoring](#automatic-scoring).

**Report.** `python -m fva report <run_dir>` writes ranked open issues to `tickets.jsonl`, a text summary to
`report.md`, and a self-contained `report.html`. The HTML page shows the raw finding count, issue counts for
closures, fix tickets and review, closures by reason code with cited evidence metadata, and every original Polaris
ID in its grouped issue. It uses inline CSS and makes no external requests. Evidence summaries, receipt details
and run summary fields other than the profile id are excluded.

**SARIF export.** `python -m fva sarif <run_dir>` writes `sast.sarif` and `sca.sarif`, plus `dast.sarif` only
when the run has DAST findings (SARIF 2.1.0, one result per original finding, never merged). The scanner finding id
is written to `guid`, so `fva.adapters.sarif` reads it back unchanged. `properties.fva` holds the verdict (a closure
triage did not auto-route shows as `needs_review`), route, reason codes, issue id and evidence as id, type, stance
and method; summaries and receipt content are excluded. Polaris import of these files is unverified.

**Polaris preview.** `python -m fva preview <run_dir>` writes `preview.jsonl` and `preview.md`: one row per
original finding with the current Polaris triage status and severity (when the run recorded them), the suggested
values from `fva/export/polaris_triage_map.py`, an `action` and `approved: false`. Only auto-routed rows can
propose a change; review rows stay open. Change rows carry the comment a future writer would post (verdict, reason
codes, issue id, evidence id/type/stance/method; never summaries or receipt content). The label map is ASSUMED. This
is a dry run: nothing is written to Polaris and every row needs approval. Runs made before `triage_status` was
recorded in `findings.jsonl` show the current status as null.

## Assess options

These options change how `python -m fva assess` runs. Output goes to `data/runs/<timestamp>-<client>/`.

| Option | What it does |
|---|---|
| `--client codex \| claude-code \| anthropic \| local` | Which model client to use. Routing between tiers is on for `codex` only. |
| `--model <name>` | One model for every cluster. Turns routing off. |
| `--no-route` | `codex` only: the senior tier for every cluster. |
| `--astra <id>` | Send the group that holds this scanner finding id to the Astra tier. Repeatable. Needs routing. |
| `--workers N` | Run N model calls in parallel. Default 1. About 4 is a sensible start. Results are the same as a sequential run. |
| `--credential-model skip` | Don't send hard-coded-credential findings to a model. Only a runtime test can decide them. Default is `ask`. Compare both with `fva score` before you switch. |
| `--prices <json>` | Per-1M-token prices by reported model name, as `{"gpt-6-sol": {"input": 2.0, "cached_input": 0.2, "output": 10.0}}`. Overrides the built-in table in `fva/reasoning/pricing.py`. `summary.json` gets a `cost` block per tier and in total; only fresh calls count toward `usd`. |
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

`--no-route` sends everything to the senior tier; `--model <name>` uses one model for everything. To keep
hard-coded-credential findings away from every model, use `--credential-model skip` (see "Assess options").

**Remapping for the company LiteLLM gateway (planned, not built).** The gateway client will use the same tiers
and variables, set to the gateway's model aliases. Known on the gateway: GPT-5.6 Luna and GPT-5.6 Sol
(GPT-6 not confirmed yet); Claude Opus / Sonnet / Haiku are alternatives. Re-run the routed comparison against
the PoC answer key after remapping, because results for one model family don't carry over to another.
The current client decision is recorded in [STATUS.md](../STATUS.md).

### Verified DAST envelope

The FVA export verifies the MCP `content[].text` JSON
envelope, with `data._items` for list results and `data` for issue details. The
listed issue fields include `id`, `weaknessId`, `context`, `occurrenceProperties`,
`triageProperties` and `_links`. Context includes `toolType`, `toolId`, `date` and
`tenantId`; the adapter drops `tenantId` and internal links.

Observed occurrence property names are `location`, `method`, `cwe`, `severity`,
`original-severity`, `attack-scope`, `attack-segment`, `attack-target`, `evidence`,
`base-risk-score`, `family-hash`, `matched-strings`, `overall-score`, `scores` and
`version`. `location` identifies the URL; `method` can be empty. The adapter retains
only the application path and never infers a missing request method. Dedicated
`parameter-name` and `parameter-location` fields are absent in this export;
`attack-target` stays a raw reference rather than an inferred parameter.

Structured `evidence[]` includes `label`, `attack.scope`, `attack.segment`,
`attack.target` and `_links[]`. Evidence links have `rel`, `href` and `method`;
their method describes artifact retrieval, not the observed application request.
The adapter keeps content-addressed references and relations, dropping artifact
URLs and raw attack targets. Inline `request` and `response-snippet` properties
are absent in this export; the older compatibility path still redacts them.

`get_issue` supplies `type.id`, `type.altName`, `type._localized.name` and
`type._localized.otherDetails`. The sidecar `dast-types.json` is keyed by original
issue ID because `weaknessId` does not identify each DAST type uniquely. Missing
type details or endpoint fields remain explicit metadata, without new reason codes.

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

`python -m fva runtime` collects and imports a small approved GET plan. This first
version supports a code-execution marker oracle for assessable SAST CWE-94 findings.
It does not generate exploits or establish SCA advisory applicability. Other cases
remain unresolved.

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
