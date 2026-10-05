"""Enriched SARIF 2.1.0 export, one file per scanner type.

  python -m fva sarif data/runs/<run>
  -> sast.sarif, sca.sarif, and dast.sarif only when the run has DAST findings

One result per original finding, never merged. The scanner's finding id is written to `guid`, the field
fva/adapters/sarif.py reads first, so the files round-trip. `properties.fva` carries verdict (the same
effective rule as report.py), route, reason codes, issue id and evidence as id/type/stance/method only:
never summaries, detail_ref or receipt content. Output is deterministic: same run directory, same bytes.
Whether Polaris accepts these files for import is unverified.
"""
from __future__ import annotations

import json
from pathlib import Path

from fva import triage
from fva.export import report, worksheet

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TYPES = ("sast", "sca", "dast")
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _result(m: dict, f: dict, ev_by_id: dict) -> dict:
    res: dict = {
        "guid": m["source_finding_id"],
        "ruleId": f.get("rule_id") or (f["cwe"][0] if f.get("cwe") else "unknown"),
        "level": _LEVEL.get(m["severity"], "warning"),
        "message": {"text": m["title"] or ""},
    }
    props: dict = {}
    if f.get("path"):
        phys = {"artifactLocation": {"uri": f["path"]}}
        if f.get("line"):
            phys["region"] = {"startLine": f["line"]}
        res["locations"] = [{"physicalLocation": phys}]
    elif f.get("endpoint"):
        res["locations"] = [{"logicalLocations": [{"name": f["endpoint"]}]}]
    if f.get("package") and "@" in f["package"]:
        name, version = f["package"].rsplit("@", 1)
        props.update(packageName=name, packageVersion=version)
    if f.get("cwe"):
        props["tags"] = sorted(f["cwe"])
    props["fva"] = {
        "verdict": report._effective(m), "route": m["route"], "reason_codes": sorted(m["reason_codes"]),
        "issue_id": m["issue_id"],
        "evidence": [{"id": i, "type": ev_by_id[i].evidence_type.value, "stance": ev_by_id[i].stance.value,
                      "method": ev_by_id[i].method} for i in sorted(m["evidence_ids"]) if i in ev_by_id]}
    res["properties"] = props
    return res


def build(run_dir: Path) -> dict[str, dict]:
    """{finding type: SARIF document} for sast and sca, plus dast when the run has DAST findings."""
    run_dir = Path(run_dir)
    rows = triage.build(run_dir)
    findings, by_finding, _profile, _trusted, _observed = worksheet.load(run_dir)
    frow = {f["finding_id"]: f for f in findings}
    ev_by_id = {e.evidence_id: e for evs in by_finding.values() for e in evs}
    out: dict[str, list[dict]] = {}
    for m in rows:
        out.setdefault(m["scanner"], []).append(_result(m, frow[m["finding_id"]], ev_by_id))
    docs = {}
    for t in TYPES:
        if t == "dast" and t not in out:
            continue
        results = sorted(out.get(t, []), key=lambda r: r["guid"])
        docs[t] = {"version": "2.1.0", "$schema": SCHEMA,
                   "runs": [{"tool": {"driver": {"name": f"fva-{t}"}}, "results": results}]}
    return docs


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    docs = build(run_dir)
    for t in TYPES:
        p = run_dir / f"{t}.sarif"
        if t in docs:
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(docs[t], sort_keys=True, indent=2) + "\n")
        elif p.exists():
            p.unlink()  # stale file from an earlier write to this directory
    return {t: len(d["runs"][0]["results"]) for t, d in docs.items()}
