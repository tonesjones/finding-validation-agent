"""fva command line.

  python -m fva assess --client codex --source "C:\\TestCode\\Juiceshop 20.2.0"
  python -m fva assess --client claude-code ...
  python -m fva assess --dry-run ...        # write prompts only, no model calls
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
    args = ap.parse_args(argv)

    from fva import pipeline
    out = Path(args.out or f"data/runs/{datetime.now():%Y%m%d-%H%M%S}-{args.client}")
    client = _client("none" if args.dry_run else args.client, args.model)
    lock = Path(args.lockfile) if args.lockfile and Path(args.lockfile).exists() else None
    summary = pipeline.run(findings_spec=args.findings, source_root=Path(args.source), profile=_profile(args.profile),
                           client=client, out_dir=out, lockfile=lock, cache_dir=Path(args.cache),
                           limit=args.limit, dry_run=args.dry_run)
    print(f"done -> {out}\n{summary}")


if __name__ == "__main__":
    main()
