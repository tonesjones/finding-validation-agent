# Finding Validation Agent

FVA checks a Polaris SAST and SCA export against the matching source checkout.
It closes findings it can prove do not apply, with a cited reason.
It leaves the rest open in a ranked report that says what evidence is missing.
This is a working prototype with no routine human review step.

## Quick start

You need Python 3.10 or newer, Git for a source checkout, and a Polaris export.
The default model client needs an installed and authenticated Codex CLI.

```bash
pip install -e .
cp examples/profiles/juiceshop.json app-profile.json
# Edit app-profile.json for your app before running assess.
python -m fva assess --findings "<export>/page-*.json" --source "<checkout>" --profile-file app-profile.json --out runs/app --cache runs/cache
python -m fva triage runs/app
python -m fva report runs/app
```

Open `runs/app/report.html` for the ranked report.
`--findings` accepts saved Polaris MCP JSON pages or one flat Polaris `.jsonl` or `.csv` file.
Flat files use the Polaris field mapping in `fva/adapters/polaris.py`.
`assess` does not accept SARIF or arbitrary scanner formats.

### Deployment profile

`--profile-file` is required. Copy [the example](examples/profiles/juiceshop.json) and edit it.
Set `profile_id` and `name` for your deployment.
Set `source_commit` to the revision that was scanned.
Set `language_packs` to `["node"]`. Only Node rules exist today.
Set `deployed_surfaces` to the surfaces that ship.
Set `extra_path_rules` for app-specific test, fixture or deployment paths.
Set `entrypoints` to the repository-relative files where your app starts.
`base_url` is optional and applies to runtime evidence.
See `DeploymentProfile` in [fva/schemas.py](fva/schemas.py) for the fields.

Pass `--lockfile <resolved-lockfile>` for installed-version checks.
There is no default lockfile. Missing SAST paths produce a warning.
See [assess options](docs/operations.md#assess-options) for other clients and flags.

## The verdicts

| Verdict | Meaning |
| --- | --- |
| `confirmed` | Supporting runtime, DAST or imported evidence proves the issue in this deployment. |
| `likely` | Static rule evidence supports the issue, without runtime proof. |
| `not_applicable` | Evidence shows the finding does not affect the shipped app. |
| `valid_non_security` | The issue is real but concerns quality or reliability rather than security. |
| `needs_review` | Evidence cannot decide the finding. It stays open. |

The model never confirms. Model output alone cannot close a finding.
`review` is an internal route name for findings that remain open, not a request for routine sign-off.
A closure that fails the triage checks stays open as `needs_review` in the report.
The safety target is zero real problems closed.

## How the pieces fit

`assess` pins the source, records rule evidence, groups related findings and asks a model about remaining clusters.
Fixed rules route Codex calls between Luna and Sol.
Only redacted code goes to the model. The assessor checks citations against the pinned source.
`triage` decides which verdicts can stand automatically.
`report` ranks open issues and records their missing evidence in `tickets.jsonl`, `report.md` and `report.html`.
Every original finding id is kept.

DAST is parked. Existing Polaris DAST findings can supply optional evidence.
SAST and SCA runs without DAST use runtime mode `none`.
Live probes are separate from the normal pipeline.

## Current results

The fresh Juice Shop run `20261005-js-fresh` on 2026-10-05 covered 573 findings.
Auto share was 0.841 and auto agreement was 0.996.
It had 0 incorrect demotions, 101 model calls and a list-price cost of $0.86.
The cached rerun cost $0 and gave identical verdicts on all 573 findings.
These are comparisons with an LLM-driven answer key that needs independent adjudication.
They do not establish general accuracy.

Record Desk supplied 6 findings, with 1 SAST and 5 SCA, on a fresh cache.
Before the rule fix, FVA auto-decided 4 of 6.
GPT-6.1 Sol checked those 4 verdicts against redacted source and agreed on 3.
Both auto-closures held. The disagreement was an over-flag on lodash CVE-2026-4800 involving template imports.
PR #44 added an option precondition.
After the fix, 3 of 6 are auto-decided. The imports closure stays open with `HIGH_IMPACT_CLOSURE`.
Six findings are thin evidence. A larger real app is the stronger test.

Every open ticket has `missing_evidence` after PR #45.
Of 73 Juice Shop tickets, 50 still get a generic SAST gap sentence.
See [STATUS.md](STATUS.md) for validation status.

## Limits

- Only Polaris is supported as scanner input. Language rules cover Node today.
- Static reachability and advisory checks cannot prove every runtime path.
- A missing DAST result or a failed probe never proves a finding is safe.
- Delivery to a security team and setup from the README on a clean machine remain unverified.
- Polaris SARIF import remains unverified. `preview` does not write to Polaris.
- Keep private exports, source content, tokens and run output out of this public repository.

## Links

- [Plan and Definition of Done](PLAN.md)
- [Remaining roadmap](ROADMAP.md)
- [Operations guide](docs/operations.md)
- [Architecture](docs/architecture.md)
- [Dated demo pitch](docs/demo-pitch.md)
- [Experiment 001](docs/experiments/001-juice-shop.md)
