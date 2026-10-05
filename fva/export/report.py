"""Ranked report and one ticket per open grouped issue.

  python -m fva report data/runs/<run>
  -> tickets.jsonl (open issues, ranked), report.md, report.html (static demo page)

Tickets carry evidence ids, type, stance and method only: never summaries or detail_ref (runtime
records may describe raw receipts). Output is deterministic: same run directory, same bytes.
"""
from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path

from fva import triage
from fva.export import worksheet
from fva.schemas import EvidenceType, Stance

# score = verdict_w * severity_w * reach_w * runtime_w, rounded to 3 decimals.
VERDICT_W = {"confirmed": 1.0, "likely": 0.7, "needs_review": 0.4, "valid_non_security": 0.05, "not_applicable": 0.0}
SEVERITY_W = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}
REACH_W = {"in_entrypoint_graph": 1.0, "imported_by_reachable_code": 1.0, "imported_by_shipped_code": 0.8,
           "not_in_entrypoint_graph": 0.5, "declared_not_imported": 0.3}
REACH_DEFAULT = 0.6      # unknown status or no reachability record
CALL_SITE = "advisory_call_site:called"   # vulnerable function is called: full reach
RUNTIME_OBSERVED_W, RUNTIME_NONE_W = 1.0, 0.8
OPEN_VERDICTS = ("confirmed", "likely", "needs_review")
STATUS = {triage.AUTO: "auto-decided", triage.REVIEW: "open, not auto-verified"}
_RUNTIME_TYPES = {EvidenceType.runtime_probe, EvidenceType.negative_control, EvidenceType.dast_observation}


def _reach(evs) -> float:
    if any(e.method == CALL_SITE for e in evs):
        return 1.0
    ws = [REACH_W.get(e.method.split(":", 1)[1], REACH_DEFAULT) for e in evs
          if e.evidence_type == EvidenceType.reachability and e.method.startswith("static_import_graph:")]
    return max(ws) if ws else REACH_DEFAULT


def _runtime(evs, trusted) -> float:
    for e in evs:
        if e.stance != Stance.supports:
            continue
        if e.evidence_type == EvidenceType.dast_observation or (
                e.evidence_type == EvidenceType.runtime_probe and e.evidence_id in trusted):
            return RUNTIME_OBSERVED_W
    return RUNTIME_NONE_W


def finding_score(verdict: str, severity: str, evs, trusted) -> float:
    return round(VERDICT_W.get(verdict, 0.0) * SEVERITY_W.get(severity, SEVERITY_W["info"])
                 * _reach(evs) * _runtime(evs, trusted), 3)


def _effective(m: dict) -> str:
    """A closure that triage did not auto-route stays open as needs_review (open, not auto-verified)."""
    return m["verdict"] if m["route"] == triage.AUTO or m["verdict"] in OPEN_VERDICTS else "needs_review"


def _read_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def _sev_max(sevs) -> str:
    return max(sevs, key=lambda s: SEVERITY_W.get(s, 0.0))


def build(run_dir: Path) -> tuple[list[dict], list[dict]]:
    """(open tickets ranked, closed issues) for one run."""
    run_dir = Path(run_dir)
    rows = triage.build(run_dir)
    findings, by_finding, _profile, trusted, _observed = worksheet.load(run_dir)
    frow = {f["finding_id"]: f for f in findings}
    ev_by_id = {e.evidence_id: e for evs in by_finding.values() for e in evs}
    primary_of = {g["issue_id"]: g["primary_finding_id"] for g in _read_jsonl(run_dir / "groups.jsonl")}

    issues: dict[str, list[dict]] = {}
    for r in rows:
        issues.setdefault(r["issue_id"] or r["finding_id"], []).append(r)

    tickets, closed = [], []
    for iid, members in issues.items():
        prim = next((m for m in members if m["finding_id"] == primary_of.get(iid)), None) \
            or next((m for m in members if m["primary"]), members[0])
        codes = sorted({c for m in members for c in m["reason_codes"]})
        cited = sorted({i for m in members for i in m["evidence_ids"]})
        evidence = [{"id": i, "type": ev_by_id[i].evidence_type.value, "stance": ev_by_id[i].stance.value,
                     "method": ev_by_id[i].method} for i in cited if i in ev_by_id]
        srcs = sorted(m["source_finding_id"] for m in members)
        if not any(_effective(m) in OPEN_VERDICTS for m in members):
            if not cited:
                raise ValueError(f"closed issue {iid} cites no evidence id")
            closed.append({"issue_id": iid, "members": srcs, "reason_codes": codes, "evidence_ids": cited,
                           "evidence": evidence, "verdict": prim["verdict"]})
            continue
        score = max(finding_score(_effective(m), m["severity"], by_finding.get(m["finding_id"], []), trusted)
                    for m in members)
        f = frow.get(prim["finding_id"], {})
        loc = f.get("endpoint") or f.get("package") or (f"{f['path']}:{f['line']}" if f.get("path") else "")
        tickets.append({
            "issue_id": iid, "score": score, "verdict": _effective(prim),
            "severity": _sev_max([m["severity"] for m in members]), "title": prim["title"], "location": loc,
            "route": triage.REVIEW if any(m["route"] == triage.REVIEW for m in members) else triage.AUTO,
            "exceptions": sorted({e for m in members for e in m["exceptions"]}),
            "reason_codes": codes, "members": srcs, "evidence": evidence})
    tickets.sort(key=lambda t: (-t["score"], t["issue_id"]))
    for n, t in enumerate(tickets, 1):
        t["rank"] = n
    closed.sort(key=lambda c: c["issue_id"])
    return tickets, closed


def write(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    tickets, closed = build(run_dir)
    with open(run_dir / "tickets.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for t in tickets:
            fh.write(json.dumps(t, sort_keys=True) + "\n")
    by_verdict = Counter(t["verdict"] for t in tickets) + Counter(c["verdict"] for c in closed)
    with open(run_dir / "report.md", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_report(tickets, closed, by_verdict))
    with open(run_dir / "report.html", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_html(tickets, closed))
    return {"open": len(tickets), "closed": len(closed), "by_verdict": dict(sorted(by_verdict.items()))}


def _html(tickets: list[dict], closed: list[dict]) -> str:
    """Render only the report's safe fields. Every finding belongs to exactly one issue."""
    def h(value) -> str:
        return escape(str(value), quote=True)

    def members(issue: dict) -> str:
        return "".join(f"<li>{h(source_id)}</li>" for source_id in issue["members"])

    def evidence(issue: dict) -> str:
        return "".join(
            f"<li>{h(e['id'])} · {h(e['type'])} · {h(e['stance'])} · {h(e['method'])}</li>"
            for e in issue["evidence"])

    fix = [t for t in tickets if t["verdict"] in ("likely", "confirmed")]
    review = [t for t in tickets if t["verdict"] not in ("likely", "confirmed")]
    by_reason: dict[str, list[dict]] = {}
    for issue in closed:
        for code in issue["reason_codes"]:
            by_reason.setdefault(code, []).append(issue)

    lines = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             "<title>Findings report</title>",
             "<style>body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;"
             "color:#17212b;background:#fff}h1,h2{line-height:1.2}section{margin:2rem 0}"
             "article{border:1px solid #ccd5dd;border-radius:.5rem;padding:1rem;margin:.75rem 0}"
             "ul{overflow-wrap:anywhere}dt{font-weight:700}dd{margin:0 0 .6rem}</style></head><body>",
             "<h1>Findings report</h1>",
             f"<p>Raw findings: {sum(len(i['members']) for i in tickets + closed)}</p>",
             "<dl>", f"<dt>Closed issues</dt><dd>{len(closed)}</dd>",
             f"<dt>Fix tickets (likely or confirmed)</dt><dd>{len(fix)}</dd>",
             f"<dt>Needs review</dt><dd>{len(review)}</dd>", "</dl>"]
    for label, issues in (("Fix tickets", fix), ("Needs review", review)):
        lines.append(f"<section><h2>{label} ({len(issues)})</h2>")
        for issue in issues:
            lines.extend((f"<article><h4>#{h(issue['rank'])} · {h(issue['severity'])} · {h(issue['title'])}</h4>",
                          f"<p>{h(issue['location'])} · issue {h(issue['issue_id'])} · "
                          f"verdict {h(issue['verdict'])}</p>",
                          f"<p>Original Polaris IDs</p><ul>{members(issue)}</ul>", "</article>"))
        lines.append("</section>")
    lines.append(f"<section><h2>Closed by reason code ({len(closed)})</h2>")
    for code, issues in sorted(by_reason.items()):
        lines.append(f"<h3>{h(code)} ({len(issues)})</h3>")
        for issue in issues:
            lines.extend((f"<article><h4>Issue {h(issue['issue_id'])}</h4>",
                          f"<p>Verdict: {h(issue['verdict'])}</p>",
                          f"<p>Original Polaris IDs</p><ul>{members(issue)}</ul>",
                          f"<p>Evidence (id · type · stance · method)</p><ul>{evidence(issue)}</ul>",
                          "</article>"))
    lines.append("</section></body></html>")
    return "\n".join(lines) + "\n"


def _cell(x) -> str:
    return str(x).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _report(tickets, closed, by_verdict) -> str:
    L = ["# Findings report", "",
         f"- Open issues: {len(tickets)}", f"- Closed issues: {len(closed)}", "",
         "## By verdict (primary finding)", "", "| Verdict | Issues |", "|---|---|"]
    L += [f"| {v} | {n} |" for v, n in sorted(by_verdict.items())]
    L += ["", "## Open issues (ranked)", "",
          "Open issues stay open until evidence decides them; nobody needs to grade them.", "",
          "| Rank | Score | Issue | Severity | Verdict | Status | Title | Location | Exceptions |",
          "|---|---|---|---|---|---|---|---|---|"]
    for t in tickets:
        L.append("| " + " | ".join(_cell(x) for x in (
            t["rank"], f"{t['score']:.3f}", t["issue_id"], t["severity"], t["verdict"], STATUS[t["route"]], t["title"],
            t["location"], " ".join(t["exceptions"]))) + " |")
    L += ["", "## Closed", "", "| Issue | Verdict | Members | Reason codes | Evidence |", "|---|---|---|---|---|"]
    for c in closed:
        L.append("| " + " | ".join(_cell(x) for x in (
            c["issue_id"], c["verdict"], " ".join(c["members"]), " ".join(c["reason_codes"]),
            " ".join(c["evidence_ids"]))) + " |")
    return "\n".join(L) + "\n"
