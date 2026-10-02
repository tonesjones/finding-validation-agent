# Finding Validation Agent

Security scanners produce long lists of possible problems. Many of them turn out not
to matter. This project is a tool that checks each one and says, with evidence,
whether it's a real problem in the app you actually ship.

## The problem

Our scanners look at an application in three ways:

- **SAST** reads the source code and flags risky patterns, like user input going
  straight into a database query.
- **SCA** lists the open-source packages the app uses and flags known
  vulnerabilities in them.
- **DAST** attacks a running copy of the app and reports what worked.

Scanners are tuned to miss as little as possible, so they over-report. In our first
test, on a practice app called OWASP Juice Shop, Polaris reported 570 findings. Most
of them fell into categories that don't need a fix:

- code that only runs in tests
- sample files that never execute
- settings for a deployment that isn't used
- package versions that aren't the ones installed

A security team has to go through that list by hand, and the same findings come back
on every scan.

## What this tool does

For each scan, the tool:

1. **Collects the results** from all three scanners, tied to the exact version of the
   code that was scanned.
2. **Merges duplicates.** One flaw often shows up three times: SAST sees the risky
   line, DAST sees the attack work, and SCA flags the package involved. The tool
   joins them into one issue.
3. **Checks each issue against the code.**
   - Does the flagged code ship, or is it test code?
   - Can a real user reach it?
   - Is the vulnerable package actually used?
   - Did the DAST scan show the attack working?
4. **Gives a verdict and shows its reasoning.** Every verdict cites the evidence it
   is based on.
5. **Ranks what's left** *(planned)*, so the team fixes the most important real problems first.

An AI model helps with step 3 when the rules alone can't decide. The model can only
add evidence. It can never mark something as confirmed on its own.

## The five verdicts

| Verdict | Meaning |
| --- | --- |
| **Confirmed** | There is evidence the problem is real in this app, such as a DAST attack that worked. |
| **Likely** | Strong static evidence (shipped, reachable, cited) but no runtime proof. Normal for apps without DAST, such as non-web apps scanned with SAST and SCA only. A reviewer's sign-off turns it into Confirmed. |
| **Not applicable** | The finding doesn't affect the shipped app, for example because it's in test code. |
| **Real, but not security** | The code issue is real, but it's a quality or reliability problem, not a security hole. |
| **Needs review** | Not enough evidence either way. The tool says what's missing so a person can finish the job. |

"Not applicable" doesn't mean the scanner was wrong. The scanner may have correctly
flagged code that simply never ships.

## How it helps the security team

- **Fewer items to review.** Findings that don't apply are closed with a written
  reason, so they don't come back on every scan.
- **Better priorities.** A problem that's confirmed, reachable and seen by DAST comes
  before a "critical" warning in a package the app never calls.
- **One fix clears several findings.** Merging is built. One ticket per merged issue
  is planned. Once it exists, fixing that issue will close the SAST, SCA and DAST
  entries together.
- **Developers know where to look.** Each ticket names the file, the line and the web
  address involved.
- **Every closure can be checked.** An auditor can see why each finding was closed.
- **Nothing is hidden.** If the tool isn't sure, the finding stays open as "Needs
  review". A finding is never marked safe just because a scanner didn't report it.

## How this differs from merging findings in Polaris

Our product team plans to link SAST, SCA and DAST findings inside Polaris, so that
fixing one clears the others. That answers "which findings are the same problem?"

This tool also answers "is that problem real in this app, and what's the proof?"
Merging duplicates shortens the list a little. Checking the evidence shortens it a
lot more.

## How a run works, step by step

```
0 export ──────► 1 assess ──► 2 worksheet ──► 3 score (automatic) ──► 4 review (optional) ──► fixes
read-only MCP    evidence     CSV + HTML      vs answer key           human decisions
```

**0. Export** (`python -m fva.polaris_mcp export --project <projectId> --branch <branchId>`) saves the Polaris
findings to `data/polaris-export/`. It uses Polaris' read-only MCP server, so it can't change anything in Polaris.
The access token comes from `POLARIS_ACCESS_TOKEN` or from `data/.polaris-token`.

**1. Assess** (`python -m fva assess --client codex --source <checkout>`), output in `data/runs/<timestamp>-<client>/`.
Two options matter for speed and cost:

- `--workers N` makes N model calls at the same time. The default is 1. About 4 is a sensible start.
- `--credential-model skip` doesn't send hard-coded-credential findings to a model, because only a runtime test can
  decide them. The default is `ask`. Compare both with `fva score` before you switch.

The steps:

1. Load the Polaris findings (SAST, SCA, and DAST when the customer has it) and record the scanner mix.
   No DAST (for example a non-web app) means runtime mode `none`: static evidence only.
2. Pin the source: a content hash of the exact files that were scanned.
3. Deployment boundary: findings in test code, sample files, unused deploy config or docs are set aside
   with a rule-based reason. No model is called for them. Each one keeps a record of the rule that set it aside
   (a `deployment_boundary` evidence record), so every closure can be checked.
4. Locate each remaining finding at its file and line; for SCA, compare the scanned package version with the
   installed one (lockfile). A version that isn't installed is set aside too. Like step 3, it keeps a
   record of the rule that set it aside (a `dependency_resolution` evidence record).
5. Static reachability: is the file reachable from the app's entrypoints, is the package imported by shipped code.
6. Link and group: an SCA package imported in a SAST finding's file, and a DAST hit on a SAST sink's route,
   are merged into one issue. Every original finding is kept.
7. Model assessment: one call per cluster (findings on the same sink or advisory), routed to a junior or senior
   model tier (see [Which AI model handles each finding](#which-ai-model-handles-each-finding)). Only redacted
   code is sent; every quoted line is checked against the real source and dropped if it doesn't match.

Files: `findings.jsonl` (every finding, its disposition and issue), `evidence.jsonl`, `assessments.jsonl`,
`groups.jsonl`, `links.jsonl`, `summary.json`.

**2. Worksheet** (`python -m fva worksheet <run_dir>`) turns the evidence into one suggested verdict per Polaris
issue id, in `worksheet.csv` (Excel) and `worksheet.html` (grouped by issue). Every suggestion passes the same
verdict rules as the rest of the tool (`fva/invariants.py`), rule closures included, because each one cites its rule
record. A model argument alone never clears or promotes a finding: "doesn't apply" from the model alone stays needs
review, and likely also needs rule evidence. Nothing is written to Polaris.

A run made before 2026-10-02 has no rule records. The worksheet warns about this and leaves those findings as needs
review until you run `assess` again. That costs nothing, because the model answers come from the cache.

**3. Score** (`python -m fva score <run_dir>`) compares the worksheet with an answer key. See
[Automatic scoring](#automatic-scoring).

**4. Review** (optional): fill `reviewer_decision` and `reviewer` in the CSV, then
`python -m fva import-review <run_dir> <csv>`. Decisions become human-review evidence (a reviewer's `confirmed`
is what turns likely into confirmed) and `review_summary.json` gives agreement per verdict.

## Polaris data tools

We want to know what Polaris actually returns, and whether its fields can help link findings that belong together.
These tools find out. They are read-only, and they write only summaries that are safe to share.

- **`python -m fva.polaris_mcp inventory`** surveys the Polaris MCP server. It lists the tools and their
  inputs, which scanner types exist in each project, and a few sample issues with full detail. The raw output stays
  in `data/`. The summary has no names, ids or URLs.
- **`python -m fva census <dir>`** counts, for each scanner type, which fields Polaris fills in and which ones fva
  ignores today. It shows values only for a few category fields, such as severity.
- **`python -m fva correlation-value [--source <checkout>]`** scores candidate ways of linking findings against the
  hand-validated answer key. The candidates are: same CWE (weakness type), same code line, same code-fragment hash,
  a package imported in the flagged file, advisory symbols near the flagged line, and CVE/BDSA aliases. Each one is
  scored on coverage (how many findings it links), ambiguity (how many other findings each link points at) and lift
  (how much knowing one finding is real raises the odds that its linked finding is real). The output is totals only.

None of these has been run against live data yet. Polaris access is pending.

## Which AI model handles each finding

Findings are grouped (same code line or advisory), and each group goes to a junior or a senior model tier.
Fixed rules in code pick the tier. The model never decides its own tier. A weak junior answer is asked once more on
the senior tier. Run `python -m fva assess` as usual; routing is on by default for `--client codex`. The routing rules,
escalation rules and the model for each tier are in
[docs/operations.md](docs/operations.md#which-ai-model-handles-each-finding).

## Automatic scoring

`python -m fva score <run_dir>` measures a run without hand review. It compares each suggested verdict with an answer
key, by default the hand-validated Juice Shop ledger. The number to watch is **incorrect demotions**: a real problem
that the tool cleared. That is the dangerous error, and the target is 0. The outcomes, metrics, output files and
limits are in [docs/operations.md](docs/operations.md#automatic-scoring).

## Testing a running app needs permission

Attacking a customer's running app requires their consent, so the tool never does it
by default. A run uses one of three runtime modes. There is no command-line flag for
the mode. It follows the scanner mix: `dast-evidence` when the scan includes DAST
results, otherwise `none`.

| Setting | Where the proof comes from | When it is used |
| --- | --- | --- |
| `none` | The code only | The scan has no DAST results (the default then) |
| `dast-evidence` | A DAST scan the customer already approved | The scan includes DAST results (the default then) |
| `live-localhost` | Safe tests against a copy running on this machine | Not built yet. Meant for practice apps like Juice Shop only |

## Where things stand

**Built and tested:**

- Reading results from Polaris (SAST and SCA) and from other scanners that
  export SARIF, a standard scanner results format
- Telling shipped code apart from tests, samples and unused settings
- Checking which package versions are actually installed
- Tracing whether flagged code can be reached from the app's starting files
- Merging SAST, SCA and DAST findings that describe the same problem
- A batch command that runs all of the above, then asks an AI model about whatever
  the rules couldn't decide, with each cluster routed to a junior or senior model
- The "likely" verdict, for apps that have no DAST
- The triage worksheet, and importing a reviewer's decisions
- Automatic scoring against an answer key
- Every closure cites the evidence it is based on
- The Polaris data tools (built, but not yet run on live data)

**Not verified:**

- DAST. The Polaris test tenant has no DAST data (checked 2026-10-02). The DAST reader
  and the SAST-to-DAST linking were built from a guessed format. They stay frozen until
  a real DAST export exists.

**Coming next:**

- Run the Polaris inventory and the correlation measurement
- A client for the company LiteLLM gateway
- One verdict per merged issue, a ranked fix list, tickets and reports
- Moving this repository to the company GitHub account, before any real customer data
  is used

The full task list is in [ROADMAP.md](ROADMAP.md). Detailed status is in
[CHECKPOINT.md](CHECKPOINT.md).

## Try it

```bash
pip install -e ".[dev]"                                          # install, with the test tools
python -m pytest                                                 # run the tests
python -m fva.polaris_mcp export --project <projectId> --branch <branchId>   # needs a Polaris token
python -m fva assess --dry-run --source <checkout>               # prepare the AI prompts without sending them
python -m fva assess --client codex --source <checkout> --workers 4
python -m fva worksheet data/runs/<run>                          # suggested verdicts, CSV + HTML
python -m fva score data/runs/<run>                              # compare with the answer key
```

`--findings` and `--lockfile` default to files under `data/`, which is local only.
The other model clients are `--client claude-code`, `--client anthropic` and
`--client local`. Results go to `data/runs/<timestamp>-<client>/`. Real scanner data stays
in `data/`, which is never committed. More options are in
[docs/operations.md](docs/operations.md#assess-options).

## First case study

The first experiment used OWASP Juice Shop 20.2.0 and 570 Polaris findings. See
[Experiment 001](docs/experiments/001-juice-shop.md).

## Ground rules

- Keep every original finding and record where each piece of evidence came from.
- Say "needs review" rather than guess.
- Never run destructive or denial-of-service tests.
- Never test a live app without permission.
- A missing DAST result never proves a finding is safe.
- Keep passwords, customer data and private scanner exports out of this repository.

This is a research project. It doesn't claim to find every vulnerability, and it
doesn't replace a human security review.
