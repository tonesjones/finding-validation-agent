# Plan: unblocked backlog

Started 2026-10-04 from main `08cd834` (517 passed, 5 skipped). Baseline run:
`data/runs/20261004-js-merged` (84.8% auto, 99.4% auto agreement, 0 incorrect demotions).
Accuracy of auto-routed rows outranks the auto share: an open finding beats a wrong closure.

Out of scope: DAST (entitlement), `--client litellm` (work laptop), the Polaris writer, the Jev
evaluation, a multi-app benchmark, expert grading of the frozen pilot.

| # | Item | Branch | Model | Fresh Codex calls |
|---|---|---|---|---|
| 1 | Credential-finding default | `claude/credential-default-plan` (this file + results) | Opus (runs are mechanical; the recommendation is judgment) | none expected; guarded |
| 2 | Exact cost accounting | `claude/cost-accounting` | Sonnet builds, Opus reviews cache-key safety | 1 smoke call, only with your OK |
| 3 | Malformed-input audit | `claude/adapter-malformed-input` | Sonnet | none |
| 4 | API client for GPT-6 | plan only, in this file | Opus | none |

Each branch starts from `main`. Every PR touches `CHECKPOINT.md`, so the later ones rebase onto
`main` after the earlier ones merge.

## 1. Credential-finding default

Juice Shop has 152 hard-coded-credential findings (CWE-798, 259, 321, 522, 547). 111 are test
files and 1 is infrastructure, so rules settle them. The other 40 go to the model under `ask`. Under
`skip` they get no model call (`model:credential_runtime_only`) and keep only their rule evidence.

Steps:
1. Run `assess` twice into `data/runs/20261004-js-cred-ask` and `-cred-skip`, then `score` and
   `triage` each.
2. Cache guard: both runs use `FVA_CODEX_CMD` pointing at a stub in the scratchpad that keeps
   `{schema}` in its argv, so the cache tag and keys stay the same, and exits non-zero. A cache miss
   then shows up as a run error instead of a Codex call. If either run reports errors, I stop and
   tell you how many calls a real run would need.
3. Compare the two runs on the 40 assessed credential findings and overall: auto share, auto
   agreement, incorrect demotions, and the confusion rows that moved.

Acceptance:
- Both runs report `errors: 0` and `cached` equal to `clusters` (no fresh calls).
- The `ask` run reproduces the baseline: 84.8% auto, 99.4% auto agreement, 0 incorrect demotions.
- A table in this file gives both modes' numbers for the credential subset and overall, with a
  recommendation, and the reasoning for it.
- The default changes only after you agree. If it changes: a test pins the new default and
  `docs/operations.md` and `CLAUDE.md` show it.

### Result (2026-10-04)

Both runs came entirely from cache under the guard: `ask` 93/93 clusters cached, `skip` 53/53, 0
errors. `skip` drops 40 clusters, all of them Luna calls.

| | `ask` | `skip` |
|---|---|---|
| Overall auto share | 84.8% | 83.9% |
| Overall auto agreement | 99.4% | 99.4% |
| Overall agreement | 0.865 | 0.856 |
| Incorrect demotions (all / auto) | 0 / 0 | 0 / 0 |
| Credential findings decided automatically (of 40) | 5, all agree | 0 |
| Credential findings left open | 35 (23 key-confirmed, 12 key-not_applicable) | 40 (28, 12) |
| Model calls on credential findings | 40 Luna, about 2.7 cents at list price | 0 |

The 5 rows that differ are `routes/login.ts:59-64`. Under `ask` they are `likely` (static reachable
sink plus a cited model `supports`) and routed auto. The PoC key calls all five confirmed active
credentials. On the other 35 the model answered neutral, and it refuted none of the 40. So
on this data the model can only promote a credential to `likely`, and it never closes one. The 12
that the key calls not_applicable stay open in both modes.

Recommendation: keep `ask` as the default. On Juice Shop it adds 5 correct automatic decisions with
no wrong ones, and `skip` saves only about 3 cents per fresh run. The evidence is thin: 5 rows, all
in one file. A wrong `likely` would be an over-flag (a ticket), not a wrong closure, and triage
already routes a model-only refutation to review. Keep `skip` as the opt-in for apps where credential
literals must not reach a model even redacted. Nothing changes in code.

Decision (owner, 2026-10-04): keep `ask`.

## 2. Exact cost accounting (CHECKPOINT backlog item 8)

Today the `tokens` field is Codex's `tokens used` footer, which counts uncached input plus output.
`codex exec --json` prints a `turn.completed` event whose `usage` has input, cached-input and output
tokens, but `--json` drops the `model:` header. The audit path in `fva/reasoning/model.py` already
recovers the model from Codex's session file (`turn_context.payload.model`, looked up by the thread id).

Design:
- The default Codex command gains `--json`. `_run` always parses the JSONL events when they are
  present: usage from `turn.completed`, model from the session file, with the `model:` header as the
  fallback for a non-JSON command. The audit-only parsing moves into this shared path.
- `<key>.meta.json` gains a `usage` object beside `agent_model` and `tokens`. Old meta files have no
  `usage` and still load.
- The cache key is unchanged: same prompt, same `model_id`, same `cache_tag` (it depends only on
  `{schema}` in argv and the schema file). A test pins a known key computed before the change.
- Prices live in one table (`fva/reasoning/pricing.py`) keyed by model name, with the CHECKPOINT list
  prices: Sol $2 / $0.20 / $10 and Luna $0.10 / $0.01 / $0.50 per 1M input / cached input / output.
  `--prices <json>` overrides the table (for the $0.01 Sol cache tier, for example). An unknown
  model gets no dollar figure and is counted, not guessed.
- `summary.json` gains a `cost` block per tier and in total: fresh calls, input, cached input, output,
  `usd` for this run's fresh calls, calls without usage, and `usd_when_first_made` for cached answers
  whose meta has usage. A fully cached run shows `usd: 0`.

Open point: whether Codex's `output_tokens` already includes `reasoning_output_tokens`. Measured
reasoning is 0 so far. The smoke call settles it, and the code charges reasoning tokens separately
only if they are not already included.

Acceptance:
- Unit tests with a fake Codex executable that prints recorded JSONL events: usage parsed, model
  read from a fake session file, a missing `turn.completed` gives "no usage", not zero.
- The cache-key test passes, and a full Juice Shop assess on the branch comes entirely from cache
  (`cached == clusters`, guarded as in item 1), with verdicts identical to `20261004-js-merged`.
- Dollar math is tested against the CHECKPOINT measured sample: Luna 0.068 cents and Sol 1.243 cents
  per call. CHECKPOINT says 1.22 cents for Sol, but its own token counts give 1.243.
- One real smoke call (`--limit 1` with an empty cache dir) shows usage, model and a dollar figure in
  `summary.json`. This is a fresh Codex call; I ask before running it.
- No token or price table is printed to logs beyond what `summary.json` holds.

## 3. Malformed-input audit (ROADMAP v0.2)

Adapters: `sarif.parse`, `mapping.load`, `polaris.load` (flat), `polaris.load_mcp`,
`polaris.load_dast`, `poc_ledger.load`. For each, tests feed broken inputs built from the existing
sanitized fixtures: truncated JSON or JSONL (cut mid-record), invalid JSON, wrong top-level type,
missing required fields, a bad SARIF version, empty files, a CSV with a missing id column, and a
bad line in the middle of a JSONL file.

Acceptance:
- Every case raises `ValueError` (or a subclass) naming the file and, where there is one, the
  record pointer. No case returns a partial list of findings.
- Each test hashes the input file before and after and checks the bytes are unchanged.
- Fixes stay in the adapters; no change to valid-input behavior. The existing adapter tests and the
  Juice Shop source tests pass unchanged.
- New fixtures, if any, are derived from the committed sanitized ones and contain no real ids.

## 4. API client for GPT-6 (CHECKPOINT backlog item 9): plan only

What it saves. Per call through Codex (measured, CHECKPOINT "Luna vs Sol comparison"): Sol
24,236 input (21,344 cached) and 238 output, Luna 23,969 (20,224 cached) and 205 output. About 20k
of that input is Codex's own system prompt; ours is about 3-4k. A direct API call sends only ours.

| Per call, list prices | Through Codex | Direct API (about 4k input, uncached) |
|---|---|---|
| Sol | 1.24 cents | about 1.04 cents |
| Luna | 0.068 cents | about 0.05 cents |
| Full fresh Juice Shop run (89 Luna + 50 Sol calls) | $0.68 | about $0.56 |

Codex's 20k tokens are mostly served from cache at a tenth of the input price, so dropping them
saves about 18%, not 6x. The bigger difference is billing: through Codex these calls come out of your
subscription, so their marginal cost is $0 until you hit its usage limits. An API client turns every
fresh run into real spend, about $0.56 per full Juice Shop run at list prices. Cached re-runs stay free
either way.

What it would take:
- A client on `OpenAICompatibleClient` with a JSON-schema `response_format`, `usage` and the model
  name read from the response (sharing item 2's usage fields), and a key from an env var that is never
  logged.
- Its `model_id` differs from the Codex client's, so it starts with an empty cache: one full fresh run
  (about $0.56) and a re-score against the PoC ledger, because answers without Codex's system prompt
  may differ.
- A data-handling check: the same redacted prompts would go to the OpenAI API instead of through
  Codex, under the API's retention terms.
- Most of this is also the `--client litellm` work for the work laptop, which is out of scope here.

Measured 2026-10-04: two real calls with Codex's prompt cache cold had 0 cached input tokens, so Sol cost 4.9
cents instead of 1.24. The savings above assume a warm cache. They are larger for sparse or one-off runs. The next
fresh full run's `cost` block will give the real hit rate.

Recommendation: don't build it now. It saves about $0.12 per fresh run at list prices and adds real
spend in place of the subscription. Build the shared parts when `--client litellm` is unblocked.

## Order

1, then 3 and 2 (independent), then 4 recorded with the item 1 results. Stop points for you: the
item 1 recommendation, the item 2 smoke call, and each green PR.

## Status

- 2026-10-04: PRs #29-#31 merged. Item 2's smoke calls passed (see CHECKPOINT); item 1 decided: `ask` stays the default (owner, 2026-10-04). All four items are done.
- 2026-10-04: plan approved. Item 1 measured: recommend keeping `ask`, waiting for your decision.
  Item 4 written up (recommendation: don't build). Items 2 and 3 in progress on their branches.
