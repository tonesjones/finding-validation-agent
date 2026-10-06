"""Triage worksheet: one row per original scanner finding, for inspecting suggestions and scoring fva.

Suggestions come from `fva.verdicts.suggest_verdict` (rules over the run's evidence, pre-v0.6 verdict
reasoner). Nothing is written to Polaris (MCP access is read-only).

  python -m fva worksheet <run_dir>                     -> worksheet.csv, worksheet.html
"""
from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path

from fva.export.polaris_triage_map import MAP_STATUS, suggest
from fva.schemas import EvidenceRecord, VerdictValue as V
from fva.verdicts import SKIP_CODES, suggest_verdict


COLUMNS = ["source_finding_id", "issue_id", "primary", "scanner", "title", "cwe", "location", "polaris_severity",
           "fva_verdict", "reason_codes", "confidence", "suggested_triage_status", "suggested_severity",
           "evidence_summary", "evidence_ids"]


def _read_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def load(run_dir: Path, *, warnings: list[str] | None = None
         ) -> tuple[list[dict], dict[str, list[EvidenceRecord]], str | None, frozenset[str]]:
    """(findings, evidence by finding id, run profile id, verified runtime ids) for one run."""
    run_dir = Path(run_dir)
    findings = _read_jsonl(run_dir / "findings.jsonl")
    if not findings:
        raise SystemExit(f"{run_dir}/findings.jsonl missing: re-run `python -m fva assess` with this version")
    summary_path = run_dir / "summary.json"
    profile = json.loads(summary_path.read_text(encoding="utf-8")).get("profile") if summary_path.exists() else None
    by_finding: dict[str, list[EvidenceRecord]] = {}
    all_evidence = []
    for d in _read_jsonl(run_dir / "evidence.jsonl"):
        e = EvidenceRecord.model_validate(d)
        all_evidence.append(e)
        for fid in e.finding_ids:
            by_finding.setdefault(fid, []).append(e)
    from fva.runtime import verify_runtime
    trusted_runtime, runtime_warning = verify_runtime(run_dir, all_evidence)
    if warnings is not None and runtime_warning:
        warnings.append(runtime_warning)
    return findings, by_finding, profile, trusted_runtime


def build(run_dir: Path, *, warnings: list[str] | None = None) -> list[dict]:
    findings, by_finding, profile, trusted_runtime = load(run_dir, warnings=warnings)
    rows = []
    for r in findings:
        evs = by_finding.get(r["finding_id"], [])
        verdict, codes, conf, cited = suggest_verdict({**r, "deployment_profile_id": profile}, evs,
                                                    verified_runtime_ids=trusted_runtime)
        status, sev = suggest(verdict, r["severity"])
        loc = r.get("endpoint") or r.get("package") or (f"{r['path']}:{r['line']}" if r.get("path") else "")
        rows.append({
            "finding_id": r["finding_id"], "disposition": r["disposition"], "source_finding_id": r["source_finding_id"],
            "issue_id": r["issue_id"],
            "primary": "yes" if r["primary"] else "", "scanner": r["finding_type"], "title": r["title"],
            "cwe": " ".join(r["cwe"]), "location": loc, "polaris_severity": r["severity"],
            "fva_verdict": verdict.value, "reason_codes": " ".join(codes), "confidence": conf,
            "suggested_triage_status": status, "suggested_severity": sev,
            "evidence_summary": " | ".join(f"{e.evidence_type.value}:{e.stance.value}" for e in cited)
                                or f"rule:{r['disposition']}",
            "evidence_ids": " ".join(e.evidence_id for e in cited)})
    rows.sort(key=lambda x: (x["issue_id"] or "", x["primary"] != "yes", x["source_finding_id"]))
    return rows


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    warnings = []
    rows = build(run_dir, warnings=warnings)
    with open(run_dir / "worksheet.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    counts = Counter(r["fva_verdict"] for r in rows)
    (run_dir / "worksheet.html").write_text(_html(rows, counts, warnings), encoding="utf-8")
    res = {"rows": len(rows), "issues": len({r["issue_id"] for r in rows}), "verdicts": dict(counts)}
    stale = sum(1 for r in rows if r["evidence_summary"].startswith("rule:") and r["disposition"] in SKIP_CODES)
    if stale:
        res["warning"] = (f"{stale} rule-skipped findings have no evidence records (run made before boundary "
                          "evidence), so they stay needs_review: re-run `python -m fva assess` (model answers come "
                          "from cache), then this command")
    if warnings:
        res["warning"] = " ".join(([res["warning"]] if "warning" in res else []) + warnings)
        res["warnings"] = warnings
    return res


def _html(rows: list[dict], counts: Counter, warnings=()) -> str:
    e = html.escape
    order = [V.confirmed, V.likely, V.needs_review, V.valid_non_security, V.not_applicable]
    head = "".join(f"<th>{c}</th>" for c in COLUMNS[:15])
    body, last = [], None
    for r in rows:
        if r["issue_id"] != last:
            body.append(f'<tr class="g"><td colspan="15">Issue {e(r["issue_id"] or "-")}</td></tr>')
            last = r["issue_id"]
        body.append("<tr>" + "".join(f'<td class="{c}">{e(str(r[c]))}</td>' for c in COLUMNS[:15]) + "</tr>")
    tally = " · ".join(f"{v.value}: {counts.get(v.value, 0)}" for v in order)
    return f"""<!doctype html><meta charset="utf-8"><title>fva triage worksheet</title>
<style>body{{font:13px system-ui;margin:16px}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;
padding:3px 6px;vertical-align:top}}tr.g td{{background:#eef;font-weight:600}}</style>
<h1>Triage worksheet</h1><p>{len(rows)} findings · {tally}</p>
{''.join(f'<p role="alert">{e(warning)}</p>' for warning in warnings)}
<p>Suggestions are provisional and not written to Polaris. Triage status mapping: {MAP_STATUS}.</p>
<table><tr>{head}</tr>{''.join(body)}</table>"""
