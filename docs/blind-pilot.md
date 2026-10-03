# Blind discovery and validation pilot

Use the local `.venv\Scripts\python.exe` in place of `python` below if the package
is not installed in your default interpreter. Evaluation/model artifacts belong under ignored `data/`.
Keep the demo in a separate private checkout and its ledger/receipts outside this repository.

On 2026-10-03 the user approved `gpt-6-sol` as the fixed pilot model while CLI
access to `gpt-6.1-sol` is unavailable. Discovery and assessment enforce the same
requested/observed model and tool audit. Preserve earlier Sol 6.1 artifacts.
Migration to Sol 6.1 requires separate smoke, batch and score directories; never
reuse a Sol 6 smoke as a Sol 6.1 response.

## Source/profile preflight

The application session supplies a JSON `DeploymentProfile` and a JSON route list.
The profile must name the route-registration file as an entrypoint as well as the
Workers adapter. Routes use the existing Express parser. Unsupported syntax produces
missing mappings and blocks DAST readiness, rather than guessing a handler.

```powershell
python -m fva eval prepare --source .\demo-source --profile-file data/eval/profile.json --expected-routes data/eval/routes.json --out data/eval/preflight
```

Outputs are `preflight.json` and `preflight.md`. The JSON includes every tracked file's
boundary and matched rule, import paths, declarations/resolved inventory, route map,
source/profile hashes, and DAST blockers. Untracked source must be committed or staged
in the application's checkout before pinning. No findings or model call are needed.
Source-only preflight also accepts an explicitly selected external `--out` directory,
such as the application's private handoff directory. The destination must not overlap
the source checkout, Git metadata or a frozen evaluation run. Discovery, case preparation,
run and score artifacts still require ignored `data/` output. No private ledger is read.
The expected route list has this shape, with the application's actual methods and paths:

```json
[{"method":"GET","path":"/example","handlers":["src/example.js"]}]
```

`assess` also accepts `--profile-file`; it is mutually exclusive with `--profile`.
Existing `assess` behavior is unchanged, including its automatic DAST linking.
Use `eval` for the pilot's approval filtering and frozen paired comparisons.

## Discovery

```powershell
python -m fva discover --source .\demo-source --profile-file data/eval/profile.json --model gpt-6-sol --out data/eval/discovery-01
```

The packet contains only redacted application code and supported package manifests,
with line numbers and dependency inventory. Markdown notes, scanner exports, receipts,
private evidence and `data/` are excluded. The packet rejects sources over its byte bound
rather than truncating them. `--max-bytes` changes that bound explicitly.
Freezing also refuses obvious plant/answer markers in comments. The marker tuple in
`fva/discovery.py` is a conservative check, not proof that a packet is blind: inspect
the frozen source for issue notes, answer hints and plant-specific tests before using
discovery results. Keep the demo repository private; obtain a new neutral source
identity and fresh discovery if hints require source changes.

`findings.jsonl` contains canonical allegations with synthesized stable IDs and raw
response pointers. `response.txt`, `call.json`, `packet.json`, and `rejected.json` retain
the response, audit, input and rejected candidates. Adjudicate rejected candidates too.
A true candidate with failed citations counts as discovery with citation failure.

## Prepare cases and review DAST links

```powershell
python -m fva eval prepare --source .\demo-source --profile-file data/eval/profile.json --expected-routes data/eval/routes.json --findings 'data/eval/polaris/page-*.json' --canonical data/eval/discovery-01/findings.jsonl --out data/eval/review-01
```

Findings and canonical inputs are repeatable and optional. Without them, this is only
preflight. Canonical findings bypass the Polaris adapter. Supply `--lockfile` for an
external resolved inventory. DAST location/method mapping was checked against six
real issue details from a separate sample project. Check the actual pilot export
with the census before trusting its fields; the sample does not prove pilot coverage.

DAST imports accept observed `location`/`method` and legacy `url`/`http-method`.
If either endpoint fact is missing, `endpoint` is absent and the missing fields are
recorded; no root path or GET method is invented. Prefer full `get_issue` records.
The exporter writes DAST details to `dast-types.json`, keyed by original issue ID,
and static details to weakness-keyed `types.json`. The importer prefers the separate
DAST sidecar; legacy DAST-only `types.json` must use original issue IDs as keys. A weakness ID
can describe multiple DAST types and is not a safe lookup key. SAST/SCA sidecars
continue to use weakness IDs.

Structured DAST evidence retains attack scope/segment and content-addressed
references into the adapter's unwrapped `/issues` view. Internal or signed download
URLs and raw attack targets stay in the original export. Artifact references are
not request/response bodies; retrieve and redact those separately when available.
Do not infer a parameter name from an unverified attack-target field.

Review `link-review.json` against the export and pinned source. Check route, handler,
parameter, CWE and scanner observation for each high-confidence link. Copy and fill
`approval-template.json` with `decision: approved`, reviewer and rationale for each
accepted link. Approval binds source/profile/export hashes, including `types.json`.
Repeat preparation into a fresh output directory with `--approved-links <filled.json>`.
Unapproved links cannot supply runtime support. Approval creates no human confirmation
evidence. Access headers are redacted before excerpts enter model packets.

`cases.jsonl` preserves every duplicate's original ID and origin. `coverage.json` keeps
DAST-only reports outside the static-case denominator. `prepared.json` hashes the frozen
case packets, redacted source, assessment prompt/schema and review artifacts. Use fresh
directories for changes; never edit a frozen packet.

## Freeze labels, smoke, then run

Have a human assign private gold rows before any responses exist. Each row uses
`case_id`, `expected_verdict` and `rationale`. Optional `verified_security` and `runtime`
fields preserve separately verified security/runtime status. The legacy key format
also remains supported. Create a label receipt containing only `reviewer`,
`prepared_sha256` from `prepared.json`, and the private gold file's SHA256 as
`gold_sha256`. The preparation and run commands accept no gold path or labels.

```powershell
python -m fva eval run data/eval/prepared-01 --model gpt-6-sol --labels-receipt data/eval/labels-receipt.json --smoke --out data/eval/smoke-01
python -m fva eval run data/eval/prepared-01 --model gpt-6-sol --labels-receipt data/eval/labels-receipt.json --smoke-run data/eval/smoke-01 --out data/eval/run-01
```

The smoke calls the first case. The batch reuses that response and calls each remaining
case once, without an assessment cache or routing. Inspect `call.json` for requested and
observed model, timing, available usage and tool audit. Missing/mismatched identity,
unexpected tools or incomplete audit stop processing. Fresh Codex calls ignore user
configuration and run in an empty directory, but isolation acceptance depends on the
event audit. Session metadata fallback reads only that call's session.

Rules-only and hybrid receive identical deterministic and approved DAST evidence.
LLM-only uses raw stances. Hybrid replays the same response through FVA citation checks
and invariants. Malformed answers remain processing failures. Raw responses are saved
directly. Each `human-review.json` row grades the one shared response and every dropped
claim. Copy that template to another file to grade it; frozen outputs must remain intact.

## Score and human adjudication

Before assessment, a human fills a private expected-label row for every case.
Use `needs_review` when the available evidence cannot decide. Use `likely` for
strong static support, and `confirmed` only with independently verified runtime
or human evidence. Record a specific rationale. A dependency advisory or a model
allegation alone does not establish exploitation. Keep blank labeling forms and
receipts outside the frozen preparation; filled labels stay in the private area.

Discovery adjudication is separate: mark each accepted and rejected candidate
as verified, refuted or unresolved, cite the independent evidence, and record
scanner overlap only after adjudication. Citation acceptance does not validate
the security claim. A rejected true candidate remains a discovery citation failure.

After the batch, copy its generated `human-review.json` to a grading file. Grade
reasoning as supported, unsupported or uncertain against the cited evidence.
Record hidden assumptions, treatment of uncertainty and whether the stated risk
matches the demonstrated path. Grade each dropped claim as correct, incorrect or
uncertain with a rationale. Keep response and packet hashes unchanged. Do not
pre-fill response grades before the model answers or use a model as the judge.

```powershell
python -m fva eval score data/eval/prepared-01 data/eval/run-01 --gold <private-gold-path> --human-review data/eval/graded-review.json
```

Scoring first verifies frozen artifacts, then loads gold and checks its receipt hash.
Headline agreement treats confirmed/likely as equivalent. Exact agreement is shown too.
LLM-only cannot produce confirmed. `score.json` records counts/denominators, failures,
DAST-backed cases/confirmed decisions and approved link references in the result rows.
Decision errors and abstention categories compare expected verdicts; they do not infer
verified security from a label alone. Unsupported reasoning and drop correctness remain
unmeasured until a human grades them. Reasoning support accepts `supported`, `unsupported`
or `uncertain`; drop correctness accepts `correct`, `incorrect` or `uncertain`.

Discovery overlap and verified LLM-only additions are separate from validation quality.
Structural case groups are reported as origins only, not logical issue overlap or
verified unique discoveries. Those metrics remain unmeasured until human issue
adjudication reconciles scanner reports, accepted/rejected discoveries and private
verification evidence. Normalized CWE strings and matching lines do not prove equivalence.
Rejected true discoveries and verified plants missed by both require separate private
human reconciliation. Pending scans are unknown, never zero findings. Keep raw failures
as replayable offline cases and retain human grades for later judge calibration. No LLM
judge is implemented. Do not tune the frozen assessment prompt during the pilot.
