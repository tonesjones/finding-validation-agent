"""fva command line.

  python -m fva assess --client codex --source "C:\\TestCode\\Juiceshop 20.2.0"
  python -m fva assess --client claude-code ...
  python -m fva assess --dry-run ...        # write prompts only, no model calls
  python -m fva worksheet data/runs/<run>   # triage worksheet (CSV + HTML) for review
  python -m fva import-review data/runs/<run> filled.csv   # reviewer decisions -> human_review evidence
"""
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

PROFILES = {"juiceshop": "fva.adapters.poc_ledger:JUICESHOP_PROFILE"}


def _profile(name: str):
    mod, attr = PROFILES[name].split(":")
    import importlib
    return getattr(importlib.import_module(mod), attr)


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
    ap = argparse.ArgumentParser(prog="python -m fva")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="collect evidence and model assessments for findings")
    a.add_argument("--client", default="codex", choices=["codex", "claude-code", "anthropic", "local", "none"])
    a.add_argument("--model", help="model to use (passed to the codex/claude CLI, or the API/local client)")
    a.add_argument("--profile", default="juiceshop", choices=sorted(PROFILES))
    a.add_argument("--source", required=True, help="path to the pinned source checkout")
    a.add_argument("--findings", default="data/polaris-export/page-*.json",
                   help="glob of Polaris MCP pages, or a flat .jsonl/.csv")
    a.add_argument("--lockfile", default="data/resolved/juiceshop-20.2.0-package-lock-resolved-2026-09-27.json")
    a.add_argument("--out", help="output dir (default data/runs/<timestamp>-<client>)")
    a.add_argument("--cache", default="data/cache/model")
    a.add_argument("--limit", type=int, help="assess only the first N clusters (smoke test)")
    a.add_argument("--dry-run", action="store_true", help="write prompts only; no model calls")
    a.add_argument("--no-route", action="store_true",
                   help="codex: GPT-6 Sol for every cluster instead of Luna/Sol routing (--model also disables routing)")
    a.add_argument("--astra", action="append", metavar="SOURCE_FINDING_ID",
                   help="send the cluster containing this scanner finding id to GPT-6 Astra (repeatable; needs routing)")
    w = sub.add_parser("worksheet", help="write worksheet.csv/.html for a run (suggestions only, nothing sent to Polaris)")
    w.add_argument("run_dir")
    r = sub.add_parser("import-review", help="turn a filled worksheet into human_review evidence and verdicts")
    r.add_argument("run_dir")
    r.add_argument("csv")
    args = ap.parse_args(argv)

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
    summary = pipeline.run(findings_spec=args.findings, source_root=Path(args.source), profile=_profile(args.profile),
                           client=client, out_dir=out, lockfile=lock, cache_dir=Path(args.cache),
                           limit=args.limit, dry_run=args.dry_run)
    print(f"done -> {out}\n{summary}")


if __name__ == "__main__":
    main()
