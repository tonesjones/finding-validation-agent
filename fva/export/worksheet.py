"""Triage worksheet: one row per original scanner finding, for review and for scoring fva.

Suggestions come from `fva.verdicts.suggest_verdict` (rules over the run's evidence, pre-v0.6 verdict
reasoner). Nothing is written to Polaris (MCP access is read-only).

  python -m fva worksheet <run_dir>                     -> worksheet.csv, worksheet.html
  python -m fva import-review <run_dir> <filled.csv>    -> reviews.jsonl, review_summary.json
"""
from __future__ import annotations

import csv
import html
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fva import reason_codes
from fva.export.polaris_triage_map import MAP_STATUS, suggest
from fva.invariants import check_verdict
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue as V
from fva.verdicts import SKIP_CODES, suggest_verdict

_NS = uuid.UUID("0f6d2b8a-4c1e-4a37-9b5d-8e2f1c3a7d60")
RULESET = "worksheet-provisional@0.1.0"

COLUMNS = ["source_finding_id", "issue_id", "primary", "scanner", "title", "cwe", "location", "polaris_severity",
           "fva_verdict", "reason_codes", "confidence", "suggested_triage_status", "suggested_severity",
           "evidence_summary", "evidence_ids", "reviewer_decision", "reviewer", "reviewer_notes"]
DECISIONS = {"agree", V.confirmed.value, V.not_applicable.value, V.valid_non_security.value, V.needs_review.value}


def _read_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []
DECISIONS = {"agree", V.confirmed.value, V.not_applicable.value, V.valid_non_security.value, V.needs_review.value}

def build(run_dir: Path) -> list[dict]:
    run_dir = Path(run_dir)
    findings = _read_jsonl(run_dir / "findings.jsonl")
    if not findings:
        raise SystemExit(f"{run_dir}/findings.jsonl missing: re-run `python -m fva assess` with this version")
    by_finding: dict[str, list[EvidenceRecord]] = {}
    for d in _read_jsonl(run_dir / "evidence.jsonl"):
        e = EvidenceRecord.model_validate(d)
        for fid in e.finding_ids:
            by_finding.setdefault(fid, []).append(e)
    rows = []
    for r in findings:
        evs = by_finding.get(r["finding_id"], [])
        verdict, codes, conf, cited = suggest_verdict(r, evs)
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
            "evidence_ids": " ".join(e.evidence_id for e in cited),
            "reviewer_decision": "", "reviewer": "", "reviewer_notes": ""})
    rows.sort(key=lambda x: (x["issue_id"] or "", x["primary"] != "yes", x["source_finding_id"]))
    return rows


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    rows = build(run_dir)
    with open(run_dir / "worksheet.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    counts = Counter(r["fva_verdict"] for r in rows)
    (run_dir / "worksheet.html").write_text(_html(rows, counts), encoding="utf-8")
    res = {"rows": len(rows), "issues": len({r["issue_id"] for r in rows}), "verdicts": dict(counts)}
    stale = sum(1 for r in rows if r["evidence_summary"].startswith("rule:") and r["disposition"] in SKIP_CODES)
    if stale:
        res["warning"] = (f"{stale} rule-skipped findings have no evidence records (run made before boundary "
                          "evidence), so they stay needs_review: re-run `python -m fva assess` (model answers come "
                          "from cache), then this command")
    return res


def _html(rows: list[dict], counts: Counter) -> str:
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
<p>Suggestions are provisional and not written to Polaris. Triage status mapping: {MAP_STATUS}.</p>
<table><tr>{head}</tr>{''.join(body)}</table>"""


def import_reviews(run_dir: Path, filled_csv: Path, *, profile_id: str | None = None) -> dict:
    """Reviewer decisions -> human_review evidence + superseding verdicts; agreement per suggested verdict."""
    run_dir = Path(run_dir)
    with open(filled_csv, encoding="utf-8-sig", newline="") as fh:
        reviewed = [r for r in csv.DictReader(fh) if (r.get("reviewer_decision") or "").strip()]
    by_src = {r["source_finding_id"]: r for r in build(run_dir)}
    out, agree = [], Counter()
    total = Counter()
    for r in reviewed:
        src = r["source_finding_id"]
        if src not in by_src:
            raise ValueError(f"worksheet row {src!r} is not in this run")
        if not (r.get("reviewer") or "").strip():
            raise ValueError(f"row {src}: reviewer name is required")
        dec = r["reviewer_decision"].strip().lower()
        if dec not in DECISIONS:
            raise ValueError(f"row {src}: reviewer_decision must be one of {sorted(DECISIONS)}")
        base = by_src[src]
        suggested = V(base["fva_verdict"])
        final = suggested if dec == "agree" else V(dec)
        total[suggested.value] += 1
        agree[suggested.value] += final is suggested
        stance = {V.confirmed: Stance.supports, V.likely: Stance.supports, V.not_applicable: Stance.refutes,
                  V.valid_non_security: Stance.non_security, V.needs_review: Stance.neutral}[final]
        fid, now = base["finding_id"], datetime.now(timezone.utc)
        ev = EvidenceRecord(evidence_id=str(uuid.uuid5(_NS, f"review:{fid}:{r['reviewer']}:{dec}")),
                            finding_ids=(fid,), evidence_type=EvidenceType.human_review, method="triage_worksheet",
                            stance=stance, summary=(r.get("reviewer_notes") or f"reviewer: {dec}")[:500],
                            collected_at=now, deployment_profile_id=profile_id or "worksheet",
                            tool_versions={"reviewer": r["reviewer"].strip(), "ruleset": RULESET})
        codes = {V.confirmed: ("REVIEWER_CONFIRMED",), V.not_applicable: ("REVIEWER_NOT_APPLICABLE",),
                 V.valid_non_security: ("QUALITY_NOT_SECURITY",), V.needs_review: ("INSUFFICIENT_EVIDENCE",),
                 V.likely: tuple(base["reason_codes"].split())}[final]
        v = Verdict(verdict_id=str(uuid.uuid5(_NS, f"verdict:{ev.evidence_id}")), finding_id=fid,
                    deployment_profile_id=ev.deployment_profile_id, verdict=final, reason_codes=codes,
                    confidence="high", evidence_ids=(ev.evidence_id,), narrative=ev.summary, decided_at=now,
                    decided_by={"method": "human", "reviewer": r["reviewer"].strip()},
                    supersedes=f"suggestion:{fid}")
        if final is not V.likely:  # likely needs rule context; the reviewer only re-affirms the suggestion
            check_verdict(v, {ev.evidence_id: ev})
        assert all(reason_codes.verdict_for(c) is final for c in codes)
        out.append({"evidence": json.loads(ev.model_dump_json()), "verdict": json.loads(v.model_dump_json()),
                    "suggested": suggested.value, "source_finding_id": src})
    with open(run_dir / "reviews.jsonl", "w", encoding="utf-8") as fh:
        for o in out:
            fh.write(json.dumps(o) + "\n")
    summary = {"reviewed": len(out), "agreement": {k: f"{agree[k]}/{n}" for k, n in sorted(total.items())},
               "agreement_rate": round(sum(agree.values()) / len(out), 3) if out else None}
    (run_dir / "review_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary
