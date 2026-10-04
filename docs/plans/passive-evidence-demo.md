# Plan: passive runtime evidence and the Polaris demo

Goal: a weekend-sized demo for the Polaris product team. Show Juice Shop's raw Polaris findings next to
FVA's result: most findings closed or grouped, the rest sent to fix tickets, few left for a person, and
every closure backed by evidence. Runtime evidence is passive only: no attack traffic, no payloads,
and passive evidence never produces `confirmed`.

Read `CLAUDE.md` and `CHECKPOINT.md` first. Their rules apply to every task here, including Codex tasks.

## Roles

- **Claude Code (Opus), lead.** Owns the evidence contract, verdict rules, invariants and review.
  Merges nothing it has not read.
- **Codex (GPT-6 Sol), worker.** Takes well-specified tasks in its own git worktree and branch, so both
  work in parallel without touching the same files. At most two Codex tasks at a time.

Delegating a task to Codex:

```powershell
git worktree add ..\fva-<task> -b codex/<task> main
cd ..\fva-<task>
codex exec -m gpt-6-sol --sandbox workspace-write "Read docs/plans/passive-evidence-demo.md, then do task <ID> only. Do not spawn subagents. Run python -m pytest before finishing."
```

Adjust the sandbox flag to your Codex version if it differs. Codex never runs `runtime approve`, never
reads or commits `data/`, and never changes `fva/invariants.py`, `fva/verdicts.py` or `fva/reason_codes.py`.
Those files belong to the lead.

When Codex finishes, the lead reviews the diff against the task's acceptance criteria, runs the full test
suite, and either merges into the integration branch or sends one round of fixes back.

## Order of work

| Step | Lead (Claude) | Codex (Sol) | Runs in parallel |
|---|---|---|---|
| 0 | Merge PR `claude/passive-whatif`; run `score` and `whatif` on the latest Juice Shop run | - | - |
| 1 | L1 evidence contract | S1 Polaris triage-field check | yes |
| 2 | L2 loaded-package collector | S2 coverage importer | yes, after L1 merges |
| 3 | L3 verdict rules | S3 label harvester (only if S1 finds triage history) | yes |
| 4 | L4 Juice Shop run and review | S4 demo report | S4 after L4 has a run |
| 5 | L5 pitch narrative and CHECKPOINT update | - | - |

## Lead tasks

### L1. Evidence contract (first, small)

- Append evidence type `runtime_observation` to `EvidenceType` in `fva/schemas.py`. Kinds:
  `loaded_package`, `line_executed`, `route_registered`, `config_state`.
- Record carries: kind, finding ids, deployment profile id, source pin, collector name and version,
  how the app was exercised (for example "npm test" or "startup only"), and a content hash of the raw file.
- `runtime_observation` is never in `CONFIRMING_TYPES` (`fva/invariants.py`). Add a test that a verdict citing
  only passive observations cannot be `confirmed`.
- Decide how it counts toward `likely`, which today needs `supports` plus rule-derived static evidence
  (`RULE_TYPES`). Record the decision in `CHECKPOINT.md`.
- Append reason codes in `fva/reason_codes.py` (append-only):
  `PACKAGE_NOT_LOADED` (not_applicable; requires no shipped import as well),
  `EXECUTED_UNDER_TEST` (likely; requires a cited static or model `supports` for SAST).
- Write the receipt JSON format in `docs/operations.md` so S2 can build against it.

Acceptance: tests pass; invariants unchanged except the new negative test; S2 can start from the doc alone.

### L2. Loaded-package collector (Node)

- A preload script run with `node --require` that records each loaded module file once at process exit.
  It records file paths only: no request data, arguments, environment values or memory contents.
- Importer maps paths to `name@version` through each package's `package.json`, binds to the source pin
  and deployment profile, and writes `runtime_observation` records.
- The operator runs the app's own test suite or a startup check with the preload. FVA sends no traffic.

Acceptance: fixture test with a tiny Node app; a package that is installed but never loaded produces no
`loaded_package` record; the receipt hash is verified on import.

### L3. Verdict rules

- SCA: vulnerable version loaded at runtime → `likely` with `VULNERABLE_VERSION_IMPORTED`, becomes a fix ticket.
  Not loaded, and static reachability shows no shipped import → `not_applicable` with `PACKAGE_NOT_LOADED`.
  Not loaded but statically imported → `needs_review` (tests may not cover it).
- SAST: line executed plus a cited `supports` → `likely` with `EXECUTED_UNDER_TEST`.
  Not executed → no change. Absence of coverage never closes a finding.
- Conflicting evidence still forces `needs_review`.

Acceptance: one test per rule above, including the two "never closes" cases.

### L4. Juice Shop run and review

Run assess with the passive observations, then `worksheet`, `score` and `whatif`. Check every new closure
against the PoC ledger. Any incorrect demotion blocks the demo until fixed.

### L5. Pitch and checkpoint

Write the narrative from the actual numbers. Update `CHECKPOINT.md` with results, decisions and next steps.

## Codex tasks

### S1. Polaris triage-field check (read-only)

Extend `python -m fva.polaris_mcp inventory` and the census to report whether issues expose a triage
status, who set it, when, and any status history. Output field names and counts only.

Acceptance: report states present or absent for each field; sanitized test fixture only; no tenant ids,
URLs or issue ids committed; only tools in `READ_ONLY_TOOLS` are called.

### S2. Coverage importer

Read V8 coverage JSON (`NODE_V8_COVERAGE` output, or c8's JSON report) collected from the app's own tests.
Map covered ranges to source lines in the pinned checkout and emit `line_executed` observations for SAST
findings whose flagged line is covered. Follow the receipt format from L1.

Acceptance: fixture with a two-file app where one flagged line is covered and one is not; paths are
normalized like `FindingLocation`; files outside the pinned source are ignored.

### S3. Label harvester (only if S1 finds triage data)

Turn Polaris dismissals into key rows (`not_applicable`), and issues that disappear in the next scan after a
code change into key rows (fixed, therefore real). Output in the answer-key format `score` already reads.

Acceptance: fixture-based tests; output never includes raw Polaris payloads.

### S4. Demo report

`python -m fva report data\runs\<run>` writes one self-contained HTML page: raw finding count, then closed,
fix tickets and needs review, closures grouped by reason code with their evidence, and grouped issues with
every original Polaris id. Static, no external requests.

Acceptance: renders from the existing worksheet fixture; no tokens, tenant ids or raw receipts in the page.

## Done means

- Full test suite green on Linux and Windows CI.
- Juice Shop result has zero incorrect demotions against the PoC ledger.
- `whatif` numbers replaced by measured counts from the passive run.
- `CHECKPOINT.md` updated; every branch merged through a PR.
