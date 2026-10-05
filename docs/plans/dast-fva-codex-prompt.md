# Codex prompt: DAST on the Polaris app "FVA"

Paste the block below into Codex from the repo root.

```
You are working in C:\TestCode\finding-validation-agent. Read CLAUDE.md, CHECKPOINT.md and
docs/plans/dast-fva-app.md first, and follow every rule in CLAUDE.md (public repo: never commit data/,
never print tokens, read-only Polaris tools only, no hosted probing, the model never confirms).

Context: the DAST entitlement is resolved. A new Polaris app "FVA" has SAST, SCA and DAST, and a DAST
scan has finished. Its project and branch ids are in data/LOCAL-NOTES.md. The DAST adapter
(fva/adapters/polaris.py from_dast_issue / load_dast) was built against an assumed envelope. Replace the
assumptions with the real one and measure what DAST adds.

Work on branch codex/dast-fva from main. Do items D0-D6 in docs/plans/dast-fva-app.md in order, and check
each acceptance criterion before moving on. Stop and report (don't guess) if the export has zero DAST
issues, the envelope can't be mapped without new reason codes, or any step would need a hosted request
or a token in output.

Use routed assessment (Luna for bulk, Sol for security-sensitive clusters and Luna `supports`
escalation) with --workers 4. Run python -m pytest before each commit. Normalize touched files to LF.
Before pushing, grep the staged files for the tenant id, Polaris hostnames and "Bearer", and put the
zero-hit result in the PR body. Update CHECKPOINT.md and PLAN.md with measured numbers (auto share, auto
agreement, incorrect demotions, link precision by tier, cost). Open a PR into main and don't merge it.
Claude will review.
```
