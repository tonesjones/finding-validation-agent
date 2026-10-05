# Plan: runtime pilot on the record-desk demo

Started 2026-10-04 from main `9f5c627` (517 passed, 5 skipped). Follows the completed
`passive-evidence-demo.md`. Local paths, ports, hashes and finding ids are in ignored
`data/LOCAL-NOTES.md` ("2026-10-03 stop point").

Rules that apply to every step:

- The owner runs `python -m fva runtime approve` in their own terminal. Claude never runs it,
  never writes or edits an approval receipt, and never drives it through an agent-created TTY.
- Requests go only to the loopback app started from the `0f17d90` clone, on the profile's port.
  GET only. No injection payloads.
- `data/` is never committed. Raw receipts never go to a model, a ticket or a committed file.

## Already checked while planning (read-only, app not started)

- The app's identity function (`source-identity.js`) uses the same algorithm as
  `fva.correlation.source_pin`: tracked files, same excluded directories, CRLF folded to LF for
  text files under 5 MiB, per-file SHA-256 chained with the path. Computed offline, the app's
  value, `pin()` on the clone and the run's `summary.json` hash are the same, and the clone is
  clean at `0f17d90`. So 1b should pass. The live header is still the check of record.
- The banner finding is `assess`, CWE-201, no refuting evidence (static, reachability and model
  are all neutral). A supporting probe with a neutral control should give `RUNTIME_CONFIRMED`.
- The header oracle accepts the banner without a literal in source, because `app.js` imports
  `express` (the `FRAMEWORK_HEADERS` rule). The scan points at `app.js:4`, which is blank at
  `0f17d90`; the code is on line 5.

## 1. Paused T6 live run (branch `claude/t6-banner-run`)

### 1a. Banner plan: one `header_disclosure` pair

Plan file `data/runtime/banner-plan.json` against base run `20261003-demo-0f17d90`:
profile and source hash from its `summary.json`, `findings_sha256` of its `findings.jsonl`,
`source_root` set to the clone. One pair:

| Field | Value |
|---|---|
| oracle | `header_disclosure` |
| probe | `GET /` |
| control | `GET /message` (no query; returns 200 with an empty escaped body, no lodash call) |
| header_name / expected_value | `X-Powered-By` / `Express` |
| allowed_urls | exactly those two URLs |

The control is not a negative. `X-Powered-By` is app-wide, so the control carries it too. The
control proves the same source-bound app answered with 200; the oracle checks the probe header.

Acceptance:
- `validate_plan` and `bind_run` pass on the plan before it goes to the owner (offline, no requests).
- The plan has no marker, no call site and no query strings.
- Claude shows the plan and its hash prefix, then stops until the owner reports approval.

### 1b. Start the app and check identity (before showing the plan)

Start `node server.js` from the clone with the profile's port, then one `GET /` to read
`X-FVA-Source-SHA256`. Stop the app if the plan waits on approval; restart it for collection.

Acceptance:
- The header equals the run's source hash. If not: no plan goes out. Diff the file lists
  (`git ls-files` vs `iter_files`) and per-file normalized hashes, report the cause, and fix
  whichever side is wrong in a separate commit with a test.
- The clone stays clean (`git status` empty) before and after.

### 1c. CVE-2021-23337: no probe (decided 2026-10-04)

The owner picked no probe. The finding stays `likely` through `VULNERABLE_FUNCTION_CALLED` and
becomes a fix ticket (upgrade lodash to 4.17.21). Nothing is sent for it.

The rejected option was an `sca_marker` probe on `/layout`. It needs an injection payload that the
owner would have to write, plus a second approval, and it does not carry over to other apps. The
verdict is already correct; a probe would only change `likely` to `confirmed`. The earlier local
validation outside FVA is not a collector receipt and stays out of FVA's decisions.

Acceptance: CHECKPOINT records the decision and the reason.

### 1d. After approval: collect, import, report

`runtime collect` into a new `data/runtime/<name>-collection`, then `runtime import` from the
base run into a new derived run, then `triage` and `report` on it. `worksheet` runs inside import.
No `score`: the demo has no answer key (decided 2026-10-04). The Juice Shop score stays the
accuracy check, and the expected demo outcome is checked directly (below).

Acceptance:
- The receipt has exactly 2 requests, both 200, both carrying the matching identity header.
- Banner: `confirmed`, `RUNTIME_CONFIRMED`, routed `auto`, citing the probe and its linked control.
- The other five findings keep their base-run verdicts. Nothing new is closed.
- `report.md`/`report.html` and `tickets.jsonl` contain no raw response bytes.
- CHECKPOINT notes that the banner confirmation is against `0f17d90` while the scan is `9ac5160`.

## 2. Pilot collector plan (plan only)

This table is the pilot collector plan (decided 2026-10-04: no separate document). For each of
the six pilot findings it sets which collector applies and why the rest get none. Nothing beyond
item 1a runs.

| Finding | Base verdict | Collector | Reason |
|---|---|---|---|
| CWE-201 banner | needs_review | `header_disclosure`, 1 pair | item 1a |
| CVE-2021-23337 (template `variable`) | likely | none | item 1c; stays a fix ticket |
| CVE-2026-4800 (template `imports`, high) | needs_review | none | needs an injection probe; the app passes no `imports` option. Stays open. |
| CVE-2020-28500 (ReDoS, `toNumber`/`trim`) | needs_review | none | DoS class; probing is out of scope. Stays open. |
| 2 x CWE-915 (prototype pollution) | not_applicable | none | already closed by `VULNERABLE_FUNCTION_NOT_CALLED` |

Passive collectors add nothing here: the demo has no test suite (only `npm start`), which is too
narrow for `PACKAGE_NOT_LOADED`, and lodash has a shipped import anyway.

Acceptance:
- Every finding has a row; every "none" names its reason.
- The only planned pair is item 1a's, and it passes `validate_plan` offline.
- Any collection beyond item 1a needs a new owner decision first.

## 3. DAST

Blocked on entitlement. No code, no plan. CHECKPOINT keeps the line "awaits entitlement; coverage unknown".

## Decisions (2026-10-04)

1. CVE-2021-23337: no probe; stays `likely` (item 1c).
2. No `score` on the demo run; the private pilot labels stay untouched.
3. Item 2 is the table above, not a separate document.

The owner's only manual step in this plan is one `runtime approve` for the banner plan.
