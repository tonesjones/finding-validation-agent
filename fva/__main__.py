"""fva command line.

  python -m fva assess --client codex --source "C:\\TestCode\\Juiceshop 20.2.0"
  python -m fva assess --client claude-code ...
  python -m fva assess --dry-run ...        # write prompts only, no model calls
  python -m fva worksheet data/runs/<run>   # triage worksheet (CSV + HTML) for review
  python -m fva import-review data/runs/<run> filled.csv   # reviewer decisions -> human_review evidence
  python -m fva score data/runs/<run>       # automatic scoring against the PoC answer key
  python -m fva whatif data/runs/<run>      # review-queue ceiling under passive runtime evidence
  python -m fva census data/polaris-export  # field census of saved Polaris responses (sanitized)
  python -m fva correlation-value [--source <checkout>]   # do candidate join keys predict the answer key?
"""
from __future__ import annotations

import argparse
import importlib
import sys
from datetime import datetime
from pathlib import Path

PROFILES = {"juiceshop": "fva.adapters.poc_ledger:JUICESHOP_PROFILE"}
# sub-commands whose module parses its own arguments
DELEGATED = {"runtime": ("fva.runtime", "approved localhost probe collection and verified import"),
             "eval": ("fva.evaluation", "blind evaluation preparation, run and score"),
             "discover": ("fva.discovery", "bounded source-only candidate discovery"),
             "census": ("fva.analysis.census", "field census of saved Polaris responses (sanitized output)"),
             "correlation-value": ("fva.analysis.correlation_value",
                                   "measure whether candidate join keys between findings predict the answer key")}


def _profile(name: str):
    mod, attr = PROFILES[name].split(":")
    return getattr(importlib.import_module(mod), attr)


def load_profile(name: str | None = None, profile_file: str | None = None):
    from fva.schemas import DeploymentProfile
    if name and profile_file:
        raise ValueError("--profile and --profile-file are mutually exclusive")
    return DeploymentProfile.model_validate_json(Path(profile_file).read_text(encoding="utf-8")) \
        if profile_file else _profile(name or "juiceshop")


def _client(name: str, model: str | None):
    from fva.reasoning import model as m
    if name == "codex":
        return m.CodexCliClient(model=model)
    if name == "claude-code":
        return m.ClaudeCodeClient(model=model)
    if name == "anthropic":
        return m.AnthropicClient(model_id=model or "claude-sonnet-5")
    if name == "local":
        import os
        return m.OpenAICompatibleClient(model_id=model or os.environ.get("FVA_LOCAL_MODEL", "local"),
                                        base_url=os.environ.get("FVA_LOCAL_MODEL_URL", "http://localhost:11434"))
    if name == "none":
        return m.ScriptedClient([], model_id="none")
    raise SystemExit(f"unknown client {name}")


def _router(args):
    """Luna/Sol routing for codex by default; one model with --model or --no-route (codex: GPT-6 Sol).
    Routing costs about 42-44% of Sol-only at list prices (measured 2026-09-28), see CHECKPOINT.md."""
    from fva.reasoning.routing import JUNIOR, SENIOR, Router, model_name
    routed = args.client == "codex" and not args.model and not args.no_route
    astra = set(args.astra or ())
    if astra and not routed:
        raise SystemExit("--astra needs routing: --client codex without --model/--no-route")
    if args.dry_run:  # no model calls; a routed plan needs only the policy
        return Router({}, astra_ids=astra) if routed else Router.single(_client("none", None))
    if not routed:
        model = args.model or (model_name(SENIOR) if args.client == "codex" else None)
        return Router.single(_client(args.client, model))
    make = lambda m: _client("codex", m)
    return Router({JUNIOR: make(model_name(JUNIOR)), SENIOR: make(model_name(SENIOR))}, make=make, astra_ids=astra)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in DELEGATED:
        return importlib.import_module(DELEGATED[argv[0]][0]).main(argv[1:])
    ap = argparse.ArgumentParser(prog="python -m fva")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, (_, text) in DELEGATED.items():
        sub.add_parser(name, help=text, add_help=False)
    a = sub.add_parser("assess", help="collect evidence and model assessments for findings")
    a.add_argument("--client", default="codex", choices=["codex", "claude-code", "anthropic", "local", "none"])
    a.add_argument("--model", help="model to use (passed to the codex/claude CLI, or the API/local client)")
    profiles = a.add_mutually_exclusive_group()
    profiles.add_argument("--profile", choices=sorted(PROFILES))
    profiles.add_argument("--profile-file", help="external DeploymentProfile JSON")
    a.add_argument("--source", required=True, help="path to the pinned source checkout")
    a.add_argument("--findings", default="data/polaris-export/page-*.json",
                   help="glob of Polaris MCP pages, or a flat .jsonl/.csv")
    a.add_argument("--lockfile", default="data/resolved/juiceshop-20.2.0-package-lock-resolved-2026-09-27.json")
    a.add_argument("--out", help="output dir (default data/runs/<timestamp>-<client>)")
    a.add_argument("--cache", default="data/cache/model")
    a.add_argument("--limit", type=int, help="assess only the first N clusters (smoke test)")
    a.add_argument("--dry-run", action="store_true", help="write prompts only; no model calls")
    a.add_argument("--workers", type=int, default=1, help="parallel model calls (default 1; about 4 is a good start)")
    a.add_argument("--credential-model", choices=["ask", "skip"], default="ask",
                   help="skip: no model call for hard-coded-credential findings (only a runtime test decides them)")
    a.add_argument("--no-route", action="store_true",
                   help="codex: GPT-6 Sol for every cluster instead of Luna/Sol routing (--model also disables routing)")
    a.add_argument("--astra", action="append", metavar="SOURCE_FINDING_ID",
                   help="send the cluster containing this scanner finding id to GPT-6 Astra (repeatable; needs routing)")
    w = sub.add_parser("worksheet", help="write worksheet.csv/.html for a run (suggestions only, nothing sent to Polaris)")
    w.add_argument("run_dir")
    r = sub.add_parser("import-review", help="turn a filled worksheet into human_review evidence and verdicts")
    r.add_argument("run_dir")
    r.add_argument("csv")
    sc = sub.add_parser("score", help="score a run against an answer key (default: the Juice Shop PoC ledger)")
    sc.add_argument("run_dir")
    sc.add_argument("--key", default="data/poc-report/final-validation-ledger.jsonl")
    wi = sub.add_parser("whatif", help="estimate the review queue under passive runtime evidence (ceiling, vs a key)")
    wi.add_argument("run_dir")
    wi.add_argument("--key", default="data/poc-report/final-validation-ledger.jsonl")
    args = ap.parse_args(argv)

    if args.cmd == "score":
        from fva.export import score
        print(score.score(Path(args.run_dir), Path(args.key)))
        return

    if args.cmd == "whatif":
        from fva.export import whatif
        print(whatif.whatif(Path(args.run_dir), Path(args.key)))
        return

    if args.cmd in ("worksheet", "import-review"):
        from fva.export import worksheet
        res = worksheet.write(Path(args.run_dir)) if args.cmd == "worksheet" else \
            worksheet.import_reviews(Path(args.run_dir), Path(args.csv))
        print(res)
        return

    from fva import pipeline
    out = Path(args.out or f"data/runs/{datetime.now():%Y%m%d-%H%M%S}-{args.client}")
    client = _router(args)
    lock = Path(args.lockfile) if args.lockfile and Path(args.lockfile).exists() else None
    if args.lockfile and lock is None:
        print(f"warning: lockfile not found: {args.lockfile} (version-drift checks disabled)", file=sys.stderr)
    summary = pipeline.run(findings_spec=args.findings, source_root=Path(args.source),
                           profile=load_profile(args.profile, args.profile_file),
                           client=client, out_dir=out, lockfile=lock, cache_dir=Path(args.cache),
                           limit=args.limit, dry_run=args.dry_run, workers=args.workers,
                           credential_model=args.credential_model)
    print(f"done -> {out}\n{summary}")


if __name__ == "__main__":
    main()
