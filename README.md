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
5. **Ranks what is left,** so the team fixes the most important real problems first.

An AI model helps with step 3 when the rules alone can't decide. The model can only
add evidence. It can never mark something as confirmed on its own.

For the security team, that means:

- **Fewer items to review.** Findings that don't apply close with a written reason, so they
  don't come back on every scan.
- **Better priorities.** A problem that is confirmed, reachable, and seen by DAST ranks above a
  "critical" warning in a package the app never calls.
- **One fix clears several findings.** Each ticket covers one merged issue and lists every SAST, SCA, and DAST
  finding in it.
- **Developers know where to look.** Each ticket names the file and line, the package, or the endpoint.
- **Every closure can be checked.** An auditor can see why each finding closed.
- **Nothing is hidden.** If the tool isn't sure, the finding stays open as "Needs review". A
  finding is never marked safe because a scanner didn't report it.

## The five verdicts

| Verdict | Meaning |
| --- | --- |
| **Confirmed** | There is evidence the problem is real in this app, such as a DAST attack that worked. |
| **Likely** | Strong static evidence (shipped, reachable, cited) but no runtime proof. This is normal for apps without DAST, such as non-web apps scanned with SAST and SCA only. A reviewer's sign-off turns it into Confirmed. |
| **Not applicable** | The finding doesn't affect the shipped app, for example because it is in test code. |
| **Real, but not security** | The code issue is real, but it is a quality or reliability problem, not a security hole. |
| **Needs review** | Not enough evidence either way. The tool says what is missing so a person can finish the job. |

"Not applicable" doesn't mean the scanner was wrong. The scanner may have correctly
flagged code that never ships.

## How this differs from merging findings in Polaris

Our product team plans to link SAST, SCA, and DAST findings inside Polaris, so that
fixing one clears the others. That answers "which findings are the same problem?"

This tool also answers "is that problem real in this app, and what is the proof?"
Merging duplicates shortens the list a little. Checking the evidence shortens it a
lot more.

## Try it

```bash
pip install -e ".[dev]"                                                      # install, with the test tools
python -m pytest                                                             # run the tests
python -m fva.polaris_mcp export --project <projectId> --branch <branchId>   # needs a Polaris token
python -m fva assess --dry-run --source <checkout>                           # write the AI prompts without sending them
python -m fva assess --client codex --source <checkout> --workers 4
python -m fva worksheet data/runs/<run>                                      # suggested verdicts, CSV and HTML
python -m fva triage data/runs/<run>                                         # decided automatically or left open
python -m fva report data/runs/<run>                                         # ranked tickets, report.md and report.html
python -m fva score data/runs/<run>                                          # compare with the answer key
python -m fva sarif data/runs/<run>                                          # enriched SARIF, one file per scanner type
python -m fva preview data/runs/<run>                                        # Polaris triage changes, dry run only
```

`--findings` and `--lockfile` default to files under `data/`, which stays local. The other model
clients are `--client claude-code`, `--client anthropic`, and `--client local`. Runs write to
`data/runs/<timestamp>-<client>/`. Scanner data never goes into the repository. The options are in
[docs/operations.md](docs/operations.md#assess-options).

## How the pieces fit together

A run goes from a Polaris export to an assessment, a worksheet, a score, and an optional human review. The
`assess` command pins the source, sets aside findings that rules can close, locates and groups the rest, and asks
a model about each cluster. Fixed rules in code route each cluster to a model tier, and the model never picks its
own tier. GPT-6 Luna answers bounded findings such as dead code. GPT-6 Sol answers security-sensitive findings.
Sol also re-checks a Luna answer that looks unreliable, refutes a high-severity finding, or supports a finding.
`python -m fva triage` then decides which findings the tool can settle automatically and which stay open.
`python -m fva score` compares the result with an answer key. The number to watch is incorrect demotions, a real
problem the tool cleared. The target is 0.

- [Operations guide, how a run works](docs/operations.md#how-a-run-works): the steps, output files, worksheet, and review commands.
- [Operations guide, model routing](docs/operations.md#which-ai-model-handles-each-finding): the routing rules and the model for each tier.
- [Operations guide, scoring](docs/operations.md#automatic-scoring): the outcomes, metrics, and limits.
- [Architecture](docs/architecture.md): the records, adapters, and runtime boundary.

## Where things stand

On Juice Shop 20.2.0, with 573 live Polaris findings and no DAST, the tool decides 483 findings (84.3%)
automatically. 99.4% of those decisions agree with the answer key from the first experiment, and none of them
clears a real problem. The other 90 stay open as "Needs review". Rules set aside 470 findings before any model
call, and the rest go to the model in 93 clusters. A run with no cached answers cost $0.83 at list prices on
2026-10-04, and a rerun with cached answers costs nothing. These numbers come from `python -m fva triage` and
`python -m fva score` on the run in [STATUS.md](STATUS.md).

Built and tested:

- Reading Polaris SAST, SCA, and DAST results, and SARIF from other scanners
- Rules that tell shipped code from tests, samples, and unused settings, plus installed-version checks and reachability
- Call-site checks for 5 lodash advisories and sanitize-html options
- Merging SAST, SCA, and DAST findings, and the "likely" verdict for apps without DAST
- The `assess` batch command with Luna and Sol routing, a model-answer cache, and a cost estimate per run
- Triage that decides findings automatically only when the evidence allows, a ranked report, and one ticket per
  open merged issue
- The triage worksheet, review import, and automatic scoring
- Enriched SARIF export and a dry-run preview of Polaris triage changes
- Runtime tests on a copy of the app on this machine: a person approves one exact plan of GET requests, and each
  test has a control request

Not done:

- The DAST scan of the pilot app, which waits on an entitlement. SAST-to-DAST links are not checked on real scans.
- Start, health check, and stop for the app under test, and browser tests. Runtime receipts keep raw responses
  on local disk.
- Call-site checks for advisories beyond lodash and sanitize-html, and links between SCA and SAST findings by call
  site
- An HTTP route, a DAST request, and a confidence for the whole issue on each ticket
- A precision metric and a benchmark across several applications
- Writing triage decisions back to Polaris. The preview's Polaris labels are not checked against Polaris.
- A client for the company LiteLLM gateway
- Moving this repository to the company GitHub account, before any real customer data is used

The task list is in [ROADMAP.md](ROADMAP.md). Detailed status is in [STATUS.md](STATUS.md).

## First case study

The first experiment used OWASP Juice Shop 20.2.0 and 570 Polaris findings. See
[Experiment 001](docs/experiments/001-juice-shop.md).

## Ground rules

- Keep every original finding and record where each piece of evidence came from.
- Say "needs review" rather than guess.
- Never run destructive or denial-of-service tests.
- Never test a live app without the owner's permission. Live tests run only through
  `python -m fva runtime`: a person approves one exact plan of GET requests to a copy on this machine.
  The scanner mix picks the runtime mode for a run: `dast-evidence` when the scan includes DAST
  results, otherwise `none`. See the [runtime boundary](docs/architecture.md#runtime-boundary).
- A missing DAST result never proves a finding is safe.
- Keep passwords, customer data, and private scanner exports out of this repository.

This is a research project. It doesn't claim to find every vulnerability, and it
doesn't replace a human security review.
