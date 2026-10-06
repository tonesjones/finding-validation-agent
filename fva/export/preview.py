"""Approval-gated Polaris triage preview. Local files only: nothing is ever sent to Polaris.

  python -m fva preview data/runs/<run>  ->  preview.jsonl, preview.md

One row per original finding. Only auto-routed rows may propose a change; every row has `approved: false`.
Comments carry ids, verdict, reason codes and evidence id/type/stance/method only: never summaries, detail_ref
or receipt content (see fva/export/report.py). Output is deterministic: same run directory, same bytes.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from fva import triage
from fva.export import worksheet
from fva.export.polaris_triage_map import MAP_STATUS, suggest
from fva.schemas import VerdictValue

NO_REVIEW = "none (open, not auto-verified)"
NO_MATCH = "none (already matches)"
CHANGE = "change"


def _comment(row: dict, evidence: list[dict]) -> str:
    ev = "; ".join(f"{e['id']} ({e['type']}/{e['stance']}/{e['method']})" for e in evidence) or "none"
    return (f"fva verdict: {row['verdict']}. Reason codes: {' '.join(row['reason_codes']) or 'none'}. "
            f"Issue: {row['issue_id'] or 'none'}. Evidence: {ev}.")


def build(run_dir: Path) -> list[dict]:
    run_dir = Path(run_dir)
    rows = triage.build(run_dir)
    findings, by_finding, _profile, _trusted = worksheet.load(run_dir)
    frow = {f["finding_id"]: f for f in findings}
    out = []
    for r in rows:
        f = frow.get(r["finding_id"], {})
        current_status = f.get("triage_status") or (f.get("scanner_metadata") or {}).get("triage_status")
        row = {"source_finding_id": r["source_finding_id"], "issue_id": r["issue_id"],
               "current_status": current_status, "current_severity": r["severity"],
               "suggested_status": None, "suggested_severity": None, "action": NO_REVIEW, "approved": False}
        if r["route"] == triage.AUTO:
            status, sev = suggest(VerdictValue(r["verdict"]), r["severity"])
            row["suggested_status"], row["suggested_severity"] = status, sev
            if status == current_status and sev == r["severity"]:
                row["action"] = NO_MATCH
            else:
                row["action"] = CHANGE
                ev_by_id = {e.evidence_id: e for e in by_finding.get(r["finding_id"], [])}
                evidence = [{"id": i, "type": ev_by_id[i].evidence_type.value, "stance": ev_by_id[i].stance.value,
                             "method": ev_by_id[i].method} for i in r["evidence_ids"] if i in ev_by_id]
                row["comment"] = _comment(r, evidence)
        out.append(row)
    out.sort(key=lambda x: (x["issue_id"] or "", x["source_finding_id"]))
    return out


def _cell(x) -> str:
    return str(x if x is not None else "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md(rows: list[dict]) -> str:
    counts = Counter(r["action"] for r in rows)
    L = ["# Polaris triage preview", "",
         f"- The status and severity label map is **{MAP_STATUS}** (`MAP_STATUS` in `fva/export/polaris_triage_map.py`).",
         "- This is a dry run: nothing was written to Polaris.",
         "- Every row needs approval (`approved` is false for all rows)."]
    unknown = sum(1 for r in rows if r["action"] == CHANGE and r["current_status"] is None)
    if unknown:
        L.append(f"- {unknown} proposed changes have no current Polaris status in this run (runs made before "
                 "`findings.jsonl` recorded it, or non-Polaris input), so they may already match.")
    L += ["", "## Rows by action", "", "| Action | Rows |", "|---|---|"]
    L += [f"| {a} | {n} |" for a, n in sorted(counts.items())]
    L += ["", "## Proposed changes", "",
          "| Finding | Issue | Current status | Suggested status | Current severity | Suggested severity |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        if r["action"] == CHANGE:
            L.append("| " + " | ".join(_cell(x) for x in (
                r["source_finding_id"], r["issue_id"], r["current_status"], r["suggested_status"],
                r["current_severity"], r["suggested_severity"])) + " |")
    return "\n".join(L) + "\n"


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    rows = build(run_dir)
    with open(run_dir / "preview.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with open(run_dir / "preview.md", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_md(rows))
    return {"rows": len(rows), "by_action": dict(sorted(Counter(r["action"] for r in rows).items()))}
