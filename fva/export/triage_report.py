"""Write the exception-routed triage for a run.

  python -m fva triage data/runs/<run>
  -> triage.jsonl (one row per finding), triage.md (counts and the review exception list)

Output is deterministic: same run directory, same bytes.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fva import triage
from fva.schemas import Severity


def _sev_rank(s: str) -> int:
    try:
        return -triage._SEV[Severity(s)]
    except ValueError:
        return 1


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    warnings: list[str] = []
    rows = triage.build(run_dir, warnings=warnings)
    with open(run_dir / "triage.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    summary = _summary(rows)
    with open(run_dir / "triage.md", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_report(rows, summary, warnings))
    return summary


def _summary(rows: list[dict]) -> dict:
    review = [r for r in rows if r["route"] == triage.REVIEW]
    by_exc = Counter(e for r in review for e in r["exceptions"])
    return {"rows": len(rows), "auto": len(rows) - len(review), "review": len(review),
            "by_exception": {e: by_exc[e] for e in triage.EXCEPTIONS if by_exc[e]}}


def _cell(x) -> str:
    return str(x).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _report(rows: list[dict], s: dict, warnings: list[str]) -> str:
    auto = [r for r in rows if r["route"] == triage.AUTO]
    review = [r for r in rows if r["route"] == triage.REVIEW]
    share = f"{s['auto'] / s['rows']:.1%}" if s["rows"] else "-"
    L = ["# Triage", "",
         f"- Findings: {s['rows']}",
         f"- Auto (no review needed): {s['auto']} ({share})",
         f"- Review queue: {s['review']}", ""]
    if warnings:
        L += ["## Warnings", ""] + [f"- {_cell(w)}" for w in sorted(set(warnings))] + [""]
    L += ["## Auto by verdict", "", "| Verdict | Count |", "|---|---|"]
    L += [f"| {v} | {c} |" for v, c in sorted(Counter(r["verdict"] for r in auto).items())]
    L += ["", "## Auto by reason code", "", "| Reason code | Count |", "|---|---|"]
    L += [f"| {c} | {n} |" for c, n in sorted(Counter(c for r in auto for c in r["reason_codes"]).items())]
    L += ["", "## Review by exception", "", "| Exception | Count |", "|---|---|"]
    L += [f"| {e} | {s['by_exception'].get(e, 0)} |" for e in triage.EXCEPTIONS]
    L += ["", "## Exception list", "",
          "| source_finding_id | scanner | severity | verdict | exceptions | title |", "|---|---|---|---|---|---|"]
    for r in sorted(review, key=lambda r: (_sev_rank(r["severity"]), r["source_finding_id"])):
        L.append("| " + " | ".join(_cell(x) for x in (r["source_finding_id"], r["scanner"], r["severity"],
                                                       r["verdict"], " ".join(r["exceptions"]), r["title"])) + " |")
    return "\n".join(L) + "\n"
