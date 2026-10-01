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
5. **Ranks what's left**, so the team fixes the most important real problems first.

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
- **One fix clears several findings.** A merged issue becomes one ticket. Fixing it
  closes the SAST, SCA and DAST entries together.
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

`--no-route` sends everything to the senior tier; `--model <name>` uses one model for everything.

**Remapping for the company LiteLLM gateway (planned, not built).** The gateway client will use the same tiers
and variables, set to the gateway's model aliases. Known on the gateway: GPT-5.6 Luna and GPT-5.6 Sol
(GPT-6 not confirmed yet); Claude Opus / Sonnet / Haiku are alternatives. Re-run the routed comparison against
the PoC answer key after remapping, because results for one model family don't carry over to another.
See `CHECKPOINT.md`, "Work laptop: LiteLLM gateway".

## Testing a running app needs permission

Attacking a customer's running app requires their consent, so the tool never does it
by default. It gets proof that a problem is real at runtime in one of three ways:

| Setting | Where the proof comes from | When to use it |
| --- | --- | --- |
| `none` | The code only | No runtime results available |
| `dast-evidence` (default) | A DAST scan the customer already approved | Normal use |
| `live-localhost` | Safe tests against a copy running on this machine | Practice apps like Juice Shop only |

## Where things stand

**Built and tested:**

- Reading results from Polaris (SAST, SCA and DAST) and from other scanners that
  export SARIF, a standard scanner results format
- Telling shipped code apart from tests, samples and unused settings
- Checking which package versions are actually installed
- Tracing whether flagged code can be reached from the app's starting files
- Merging SAST, SCA and DAST findings that describe the same problem
- Using an approved DAST scan as proof that a problem is real
- A batch command that runs all of the above, then asks an AI model about whatever
  the rules couldn't decide

**Not yet tested on real data:**

- The DAST reader. It was built from a guessed format and needs checking against a
  real Polaris DAST export.

**Coming next:**

- Final verdicts for each merged issue, a ranked fix list and reports
- Measuring accuracy against findings that people have already reviewed
- Moving this repository to a company GitHub account, before any real customer data
  is used

The full task list is in [ROADMAP.md](ROADMAP.md). Detailed status is in
[CHECKPOINT.md](CHECKPOINT.md).

## Try it

```bash
pip install -e .
python -m pytest                                               # run the tests
python -m fva assess --dry-run --source <path-to-juice-shop>   # prepare the AI prompts without sending them
python -m fva assess --client claude-code --source <path-to-juice-shop>
```

Results go to `data/runs/<timestamp>-<client>/`. Real scanner data stays in `data/`,
which is never committed.

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
