"""Triage worksheet: one row per original scanner finding, for review and for scoring fva.

Suggestions here are provisional (rules over the run's evidence, pre-v0.6 verdict reasoner). Every
suggestion that cites evidence passes `fva.invariants.check_verdict`; anything that would not falls
back to needs_review. Nothing is written to Polaris (MCP access is read-only).

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
from fva.invariants import InvariantError, check_verdict
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue as V

_NS = uuid.UUID("0f6d2b8a-4c1e-4a37-9b5d-8e2f1c3a7d60")
RULESET = "worksheet-provisional@0.1.0"

COLUMNS = ["source_finding_id", "issue_id", "primary", "scanner", "title", "cwe", "location", "polaris_severity",
           "fva_verdict", "reason_codes", "confidence", "suggested_triage_status", "suggested_severity",
           "evidence_summary", "evidence_ids", "reviewer_decision", "reviewer", "reviewer_notes"]
DECISIONS = {"agree", V.confirmed.value, V.not_applicable.value, V.valid_non_security.value, V.needs_review.value}

_SKIP_CODES = {
    "surface:test": "TEST_ONLY", "surface:fixture": "NON_EXECUTABLE_FIXTURE",
    "surface:infrastructure": "UNUSED_DEPLOYMENT_CONFIG", "surface:api_spec": "DOCUMENTATION_ONLY",
    "surface:documentation": "DOCUMENTATION_ONLY", "dependency:version_drift": "VERSION_DRIFT",
    "dependency:not_installed": "VERSION_DRIFT",
}
_RULE_CONTEXT = {EvidenceType.static_source, EvidenceType.reachability, EvidenceType.dependency_resolution}


def _read_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def _check(fid: str, verdict: V, codes: tuple[str, ...], evs: list[EvidenceRecord], conf: str) -> bool:
    try:
        check_verdict(Verdict(verdict_id="probe", finding_id=fid, deployment_profile_id=evs[0].deployment_profile_id,
                              verdict=verdict, reason_codes=codes, confidence=conf,
                              evidence_ids=tuple(e.evidence_id for e in evs), narrative="-",
                              decided_at=datetime.now(timezone.utc), decided_by={"method": "rules"}),
                      {e.evidence_id: e for e in evs})
        return True
    except InvariantError:
        return False


def suggest_verdict(row: dict, evs: list[EvidenceRecord]) -> tuple[V, tuple[str, ...], str, list[EvidenceRecord]]:
    """(verdict, reason codes, confidence, cited evidence) for one finding."""
    disp = row["disposition"]
    if disp in _SKIP_CODES:  # deployment-boundary / dependency rules: decided before any model call
        return V.not_applicable, (_SKIP_CODES[disp],), "high", evs
    if disp.startswith(("surface:", "dependency:", "reachability:")):
        return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs
    stances = {e.stance for e in evs}
    dast = [e for e in evs if e.evidence_type is EvidenceType.dast_observation and e.stance is Stance.supports]
    if dast and Stance.refutes not in stances:
        return V.confirmed, ("DAST_OBSERVED",), "high", evs
    if Stance.supports in stances and Stance.refutes in stances:
        return V.needs_review, ("CONFLICTING_EVIDENCE",), "medium", evs
    if Stance.non_security in stances and Stance.supports not in stances:
        if _check(row["finding_id"], V.valid_non_security, ("QUALITY_NOT_SECURITY",), evs, "medium"):
            return V.valid_non_security, ("QUALITY_NOT_SECURITY",), "medium", evs
    if Stance.supports in stances:
        code = "VULNERABLE_VERSION_IMPORTED" if row["finding_type"] == "sca" else "STATIC_REACHABLE_SINK"
        if any(e.evidence_type in _RULE_CONTEXT for e in evs) and _check(row["finding_id"], V.likely, (code,),
                                                                          evs, "medium"):
            return V.likely, (code,), "medium", evs
    # A model refutation alone stays needs_review here: which not_applicable reason applies is a reviewer call.
    return V.needs_review, ("INSUFFICIENT_EVIDENCE",), "low", evs


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
            "finding_id": r["finding_id"], "source_finding_id": r["source_finding_id"], "issue_id": r["issue_id"],
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
    return {"rows": len(rows), "issues": len({r["issue_id"] for r in rows}), "verdicts": dict(counts)}


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
