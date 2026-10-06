"""fva command line.

  python -m fva assess --client codex --source "C:\\TestCode\\Juiceshop 20.2.0"
  python -m fva assess --client claude-code ...
  python -m fva assess --dry-run ...        # write prompts only, no model calls
  python -m fva worksheet data/runs/<run>   # triage worksheet (CSV + HTML) for review
  python -m fva triage data/runs/<run>      # auto vs review routing (triage.jsonl, triage.md)
  python -m fva score data/runs/<run>       # automatic scoring against the PoC answer key
"""
from __future__ import annotations

import argparse
import importlib
import sys
from datetime import datetime
from pathlib import Path

# sub-commands whose module parses its own arguments
DELEGATED = {"runtime": ("fva.runtime", "approved localhost probe collection and verified import")}


def load_profile(profile_file: str):
    from fva.schemas import DeploymentProfile
    return DeploymentProfile.model_validate_json(Path(profile_file).read_text(encoding="utf-8"))


def missing_sast_paths(findings, source_root: Path) -> list[str]:
    """Return SAST paths that are absent from the source checkout."""
    root = source_root.resolve()
    missing = []
    for finding in findings:
        if finding.finding_type.value != "sast" or finding.location is None:
            continue
        candidate = (root / finding.location.path).resolve()
        if not candidate.is_relative_to(root) or not candidate.exists():
            missing.append(finding.location.path)
    return missing


def warn_missing_sast_paths(findings, source_root: Path) -> None:
    total = sum(f.finding_type.value == "sast" and f.location is not None for f in findings)
    missing = missing_sast_paths(findings, source_root)
    if missing:
        print(f"warning: {len(missing)} of {total} SAST finding paths not found under {source_root}",
              file=sys.stderr)
        print("  examples: " + ", ".join(missing[:5]), file=sys.stderr)


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
    Routing costs about 42-44% of Sol-only at list prices (measured 2026-09-28), see STATUS.md."""
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
    a.add_argument("--profile-file", required=True, help="DeploymentProfile JSON")
    a.add_argument("--source", required=True, help="path to the pinned source checkout")
    a.add_argument("--findings", default="data/polaris-export/page-*.json",
                   help="glob of Polaris MCP pages, or a flat .jsonl/.csv")
    a.add_argument("--lockfile")
    a.add_argument("--out", help="output dir (default data/runs/<timestamp>-<client>)")
    a.add_argument("--cache", default="data/cache/model")
    a.add_argument("--limit", type=int, help="assess only the first N clusters (smoke test)")
    a.add_argument("--dry-run", action="store_true", help="write prompts only; no model calls")
    a.add_argument("--workers", type=int, default=1, help="parallel model calls (default 1; about 4 is a good start)")
    a.add_argument("--credential-model", choices=["ask", "skip"], default="ask",
                   help="skip: no model call for hard-coded-credential findings (only a runtime test decides them)")
    a.add_argument("--no-route", action="store_true",
                   help="codex: GPT-6 Sol for every cluster instead of Luna/Sol routing (--model also disables routing)")
    a.add_argument("--prices", help="JSON file of per-1M-token prices by model name (overrides the built-in table)")
    a.add_argument("--astra", action="append", metavar="SOURCE_FINDING_ID",
                   help="send the cluster containing this scanner finding id to GPT-6 Astra (repeatable; needs routing)")
    w = sub.add_parser("worksheet", help="write worksheet.csv/.html for a run (suggestions only, nothing sent to Polaris)")
    w.add_argument("run_dir")
    t = sub.add_parser("triage", help="write triage.jsonl/triage.md: auto vs review routing for a run")
    t.add_argument("run_dir")
    rp = sub.add_parser("report", help="write tickets.jsonl/report.md: ranked open issues, one ticket each")
    rp.add_argument("run_dir")
    sa = sub.add_parser("sarif", help="write sast.sarif/sca.sarif (and dast.sarif if any): enriched SARIF export")
    sa.add_argument("run_dir")
    pv = sub.add_parser("preview", help="write preview.jsonl/preview.md: proposed Polaris triage (dry run)")
    pv.add_argument("run_dir")
    sc = sub.add_parser("score", help="score a run against an answer key (default: the Juice Shop PoC ledger)")
    sc.add_argument("run_dir")
    sc.add_argument("--key", default="data/poc-report/final-validation-ledger.jsonl")
    args = ap.parse_args(argv)

    if args.cmd == "score":
        from fva.export import score
        print(score.score(Path(args.run_dir), Path(args.key)))
        return

    if args.cmd == "triage":
        from fva.export import triage_report
        print(triage_report.write(Path(args.run_dir)))
        return

    if args.cmd == "report":
        from fva.export import report
        print(report.write(Path(args.run_dir)))
        return

    if args.cmd == "sarif":
        from fva.export import sarif_export
        print(sarif_export.write(Path(args.run_dir)))
        return

    if args.cmd == "preview":
        from fva.export import preview
        print(preview.write(Path(args.run_dir)))
        return

    if args.cmd == "worksheet":
        from fva.export import worksheet
        print(worksheet.write(Path(args.run_dir)))
        return

    from fva import pipeline
    from fva.reasoning import pricing
    out = Path(args.out or f"data/runs/{datetime.now():%Y%m%d-%H%M%S}-{args.client}")
    client = _router(args)
    source_root = Path(args.source)
    warn_missing_sast_paths(pipeline.load_findings(args.findings), source_root)
    lock = Path(args.lockfile) if args.lockfile and Path(args.lockfile).exists() else None
    if args.lockfile and lock is None:
        print(f"warning: lockfile not found: {args.lockfile} (version-drift checks disabled)", file=sys.stderr)
    summary = pipeline.run(findings_spec=args.findings, source_root=source_root,
                           profile=load_profile(args.profile_file),
                           client=client, out_dir=out, lockfile=lock, cache_dir=Path(args.cache),
                           limit=args.limit, dry_run=args.dry_run, workers=args.workers,
                           credential_model=args.credential_model,
                           prices=pricing.load_prices(Path(args.prices)) if args.prices else None)
    print(f"done -> {out}\n{summary}")


if __name__ == "__main__":
    main()
