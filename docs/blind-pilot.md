# Blind discovery and validation pilot

This guide runs the pilot end to end: preflight the demo source, let a model look for
candidates without seeing scanner results, prepare frozen cases, freeze human labels,
run the paired assessment, and score it.

## Before you start

- If the package isn't installed in your default interpreter, use the local
  `.venv\Scripts\python.exe` in place of `python` in the commands below.
- Write evaluation and model artifacts under the ignored `data/` directory.
- Keep the demo in a separate private checkout. Keep its ledger and receipts outside
  this repository.

On 2026-10-03 the user approved `gpt-6-sol` as the fixed pilot model, because CLI
access to `gpt-6.1-sol` is unavailable. Discovery and assessment both check that the
observed model matches the requested model, and both audit tool use. Keep earlier
Sol 6.1 artifacts. A move to Sol 6.1 needs its own smoke, batch and score directories.
Never reuse a Sol 6 smoke as a Sol 6.1 response.

## Run the source and profile preflight

The application session supplies a JSON `DeploymentProfile` and a JSON route list.
The profile must name both the route-registration file and the Workers adapter as
entrypoints. Routes are read with the existing Express parser. Syntax the parser
doesn't support produces a missing mapping and blocks DAST readiness. The parser
never guesses a handler.

```powershell
python -m fva eval prepare --source .\demo-source --profile-file data/eval/profile.json --expected-routes data/eval/routes.json --out data/eval/preflight
```

The command writes `preflight.json` and `preflight.md`. The JSON lists, for every
tracked file, its boundary, matched rule and import path. It also holds the declared
and resolved dependency inventory, the route map, the source and profile hashes, and
the reasons DAST is blocked. Preflight needs no findings and makes no model call.

Commit or stage new source files in the application's checkout before you pin it.
Pinning reads tracked files only.

Preflight can write to an external `--out` directory that you select, such as the
application's private handoff directory. That directory must not overlap the source
checkout, Git metadata or a frozen evaluation run. Discovery, case preparation, run
and score still write only under `data/`. No step reads the private ledger.

The expected route list has this shape. Use the application's real methods and paths:

```json
[{"method":"GET","path":"/example","handlers":["src/example.js"]}]
```

`assess` also accepts `--profile-file`, which can't be combined with `--profile`.
Nothing else in `assess` changes, including its automatic DAST linking. Use `eval`
for the pilot's link approvals and frozen paired comparison.

## Run discovery

```powershell
python -m fva discover --source .\demo-source --profile-file data/eval/profile.json --model gpt-6-sol --out data/eval/discovery-01
```

The model sees only redacted application code and supported package manifests, with
line numbers and the dependency inventory. Markdown notes, scanner exports, receipts,
private evidence and `data/` are left out. If the source is larger than the byte limit,
discovery stops instead of truncating it. To change the limit, pass `--max-bytes`.

Freezing stops if a code comment contains an obvious plant or answer marker. The
markers live in `PLANT_COMMENT_MARKERS` in `fva/discovery.py`. They are a rough check
and don't prove the packet is blind. Before you use discovery results, read the frozen source for
issue notes, answer hints and tests written for a plant. Keep the demo repository
private. If removing a hint means changing the source, the source needs a new neutral
identity and a fresh discovery run.

Discovery writes these files:

- `findings.jsonl`: accepted candidates as canonical findings, with stable synthesized
  IDs and pointers into the raw response.
- `response.txt`: the raw model response.
- `call.json`: the model identity and the call audit.
- `packet.json`: the exact model input.
- `rejected.json`: candidates whose schema or citations failed.

Adjudicate rejected candidates too. A true candidate with failed citations counts as a
discovery with a citation failure.

## Prepare cases and review DAST links

```powershell
python -m fva eval prepare --source .\demo-source --profile-file data/eval/profile.json --expected-routes data/eval/routes.json --findings 'data/eval/polaris/page-*.json' --canonical data/eval/discovery-01/findings.jsonl --out data/eval/review-01
```

`--findings` and `--canonical` are optional and repeatable. Without either one, the
command runs preflight only. Canonical findings skip the Polaris adapter. To use an
external resolved inventory, pass `--lockfile`.

The DAST location and method mapping was checked against six real issue details from
a separate sample project. That sample doesn't prove the pilot's coverage. Run the
census on the real pilot export before you trust its fields.

The DAST importer reads `location` and `method`, and falls back to the older `url` and
`http-method`. If either value is missing, the finding has no `endpoint` and records
which fields are missing. The importer never invents a root path or a GET method.
Prefer full `get_issue` records.

The exporter writes DAST type details to `dast-types.json`, keyed by original issue ID,
and static type details to `types.json`, keyed by weakness ID. One weakness ID can
cover several DAST types, so it is not a safe key for DAST. The importer reads DAST
types from `dast-types.json`. An older export that has only `types.json` still works if
that file keys its DAST entries by original issue ID.

Structured DAST evidence keeps the attack scope and segment, plus content-addressed
references into the adapter's unwrapped `/issues` view. Internal or signed download
URLs and raw attack targets stay in the original export. An artifact reference is not a
request or response body. Retrieve and redact bodies separately when they exist. Don't
infer a parameter name from an unverified attack-target field.

To approve DAST links:

1. Open `link-review.json` next to the export and the pinned source.
2. For each high-confidence link, check the route, handler, parameter, CWE and scanner
   observation.
3. Copy `approval-template.json`. For each link you accept, set `decision` to
   `approved` and fill in `reviewer` and `rationale`.
4. Run preparation again into a new output directory with
   `--approved-links <filled.json>`.

An approval is bound to the source, profile and export hashes, including `types.json`
and `dast-types.json`. Unapproved links can't supply runtime support. An approval is not
human confirmation evidence. Access headers are redacted before any excerpt reaches a
model packet.

`cases.jsonl` keeps every duplicate's original ID and origin. `coverage.json` counts
DAST-only reports outside the static-case denominator. `prepared.json` hashes the frozen
case packets, the redacted source, the assessment prompt and schema, and the review
files. To change anything, prepare into a new directory. Never edit a frozen packet.

## Freeze labels, then run the smoke and the batch

Before any model response exists, a human writes a private gold row for every case.
Each row has `case_id`, `expected_verdict` and `rationale`:

- Use `needs_review` when the available evidence can't decide.
- Use `likely` for strong static support.
- Use `confirmed` only with independently verified runtime or human evidence.
- Write a specific rationale. A dependency advisory or a model allegation alone doesn't
  show exploitation.

Optional `verified_security` and `runtime` fields record security and runtime status
that was verified separately. The older ledger format still loads. Keep blank labeling
forms and receipts outside the frozen preparation, and keep filled labels in the
private area.

Then create a label receipt with only three fields. `reviewer` names the person who
labeled. `prepared_sha256` comes from `prepared.json`. `gold_sha256` is the SHA-256 of
the private gold file. Preparation and run accept no gold path and no labels.

```powershell
python -m fva eval run data/eval/prepared-01 --model gpt-6-sol --labels-receipt data/eval/labels-receipt.json --smoke --out data/eval/smoke-01
python -m fva eval run data/eval/prepared-01 --model gpt-6-sol --labels-receipt data/eval/labels-receipt.json --smoke-run data/eval/smoke-01 --out data/eval/run-01
```

The smoke calls the model for the first case. The batch reuses that response and calls
the model once for each remaining case, with no assessment cache and no routing. Each
`call.json` records the requested and observed model, timing, available usage and the
tool audit. Processing stops on a missing or mismatched model identity, unexpected tool
use, or an incomplete audit. Each Codex call ignores user configuration and runs in an
empty directory. The event audit is what proves isolation. If the CLI doesn't report the
model, the client reads only that call's own session metadata.

Rules-only and hybrid get the same deterministic evidence and the same approved DAST
evidence. LLM-only maps the raw claim stances. Hybrid replays the same response through
FVA's citation checks and invariants. A malformed answer is recorded as a processing
failure. Raw responses are saved as received.

## Score the run and adjudicate discovery

Routine triage does not require a person to grade every model response. Use the model's
cited evidence and confidence to route clear cases, and reserve human review for low
confidence, missing/invalid citations, conflicting evidence and decisions with material
impact. Keep those operator decisions separate from the frozen benchmark.

For a completed paired run, python -m fva eval status reports aggregate run state,
model/audit gates, response count and processing failures. It verifies that the sealed
run belongs to the frozen preparation and uses the same label receipt. It does not
display or interpret response contents, and never opens gold. The score still measures
agreement with the prewritten labels; that alone does not establish security accuracy.

    python -m fva eval status data/eval/prepared-01 data/eval/run-01 --receipt data/eval/labels-receipt.json

After the batch, copy its `human-review.json` to a new grading file. The frozen outputs
must stay unchanged. Each row covers one shared response and every claim FVA dropped
from it. For each row:

This optional grading measures reasoning quality for the benchmark; it is not an
operator prerequisite for using evidence-backed triage.

- Grade the reasoning as `supported`, `unsupported` or `uncertain` against the cited
  evidence.
- Record hidden assumptions, how the response treats uncertainty, and whether the stated
  risk matches the demonstrated path.
- Grade each dropped claim as `correct`, `incorrect` or `uncertain`, with a rationale.
- Leave the response and packet hashes unchanged.

Don't fill in grades before the model answers, and don't use a model as the judge.

```powershell
python -m fva eval score data/eval/prepared-01 data/eval/run-01 --gold <private-gold-path> --human-review data/eval/graded-review.json
```

Scoring verifies the frozen artifacts first, then loads the gold file and checks it
against the receipt hash. Headline agreement counts `confirmed` and `likely` as the same
answer. Exact agreement is reported too. LLM-only can't produce `confirmed`.

`score.json` records counts with their denominators, processing failures, DAST-backed
cases and confirmed decisions, and the approved link references in each result row.
Decision errors and abstention categories compare against the expected verdicts. They
don't treat a label alone as verified security. Unsupported reasoning and drop
correctness stay unmeasured until a human grades them.

Discovery adjudication is separate from validation quality. For each accepted and
rejected candidate, mark it verified, refuted or unresolved, and cite the independent
evidence. A verified citation doesn't validate the security claim. A rejected true
candidate still counts as a discovery citation failure.

Scoring reports only which origins each structural case group came from. It doesn't
measure overlap between discovery and Polaris, or verified discoveries that only the
model made. Those stay unmeasured until a human reconciles the scanner reports, the
accepted and rejected candidates, and the private verification evidence. Matching CWEs
or lines don't prove two reports describe the same issue. Rejected true discoveries,
and verified plants that both missed, also need separate private reconciliation.

A pending scan is unknown, never zero findings. Keep raw failures as replayable offline
cases, and keep human grades for later judge calibration. No LLM judge exists yet. Don't
tune the frozen assessment prompt during the pilot.
