# Demo script: 10-minute walkthrough for an internal team

Numbers are in [demo-pitch.md](demo-pitch.md). Paths below are placeholders; fill them in locally.

## Before the demo

- Run `pip install -e .` once from the repo root.
- Check out Juice Shop 20.2.0 and note the path as `<juice-shop-checkout>`.
- Place a Polaris export locally under `data/` (never commit it) and keep the resolved npm lockfile as
  `<resolved-lockfile>`.
- Warm the model cache by running the assess step once beforehand. A warm cache means the demo run costs $0.
  Clusters with no cached answer will call the model, so do the rehearsal run first.
- Do a rehearsal run and note the run directory as `<run>` (`data\runs\<timestamp>-codex`).

## Steps

1. Assess (about 2 minutes, cached). Say what it does: pins the source, gathers evidence, asks the model only about
   what the rules cannot settle.

   ```powershell
   python -m fva assess --client codex --source "<juice-shop-checkout>" --profile-file examples/profiles/juiceshop.json --lockfile <resolved-lockfile>
   ```

2. Triage (under 1 minute). Splits auto decisions from open findings.

   ```powershell
   python -m fva triage <run>
   ```

3. Report (under 1 minute).

   ```powershell
   python -m fva report <run>
   ```

4. Open `<run>\report.html` and walk through it (5 minutes). Lead with the headline: 573 findings, 499 issues,
   74 open, 425 closed.

## What to show in report.html

- One closure. Show its cited evidence and its reason code, for example `TEST_ONLY`. Point out that a rule made it.
- One `likely` ticket. Show the rule-derived evidence behind it. Say that `likely` is not `confirmed`.
- One `needs_review` ticket. Read its missing-evidence sentence aloud. This is what would settle it.
- One former version-drift finding, now open. Explain that the old rule closed it without checking the installed
  version was unaffected, and that it now goes to assessment.

## What's next

- Run on an untuned app: Node-RED 5.0.8.
- Auth-level checks, as a design proposal only. Nothing is built.
- Independent adjudication of the answer key.

## Questions to expect

- **Can I trust the 99.4%?** It is measured against an LLM-built answer key that nobody has independently
  adjudicated. It is a consistency measure until that happens.
- **Does it confirm vulnerabilities?** No. Nothing is `confirmed` without runtime evidence, and runtime probes and
  DAST are parked. The best it says is `likely`.
- **Will it work on our app?** Not shown yet. Generalization to an untuned app is open; Node-RED is the next test.
- **Why did the auto share drop?** 20 findings the old `VERSION_DRIFT` rule closed without checking the installed
  version. They are open now, and 19 model clusters await fresh answers.
- **Are the quality-checker closures safe?** The 32 `QUALITY_NOT_SECURITY` closures are under review, because a
  no-effect statement can be a security bug.
