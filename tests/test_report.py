import json
from html import escape

import pytest

from fva import __main__ as cli
from fva.export import report
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q; one issue each)


def _tickets(run):
    return [json.loads(x) for x in (run / "tickets.jsonl").read_text(encoding="utf-8").splitlines()]


def test_ranking_and_score_math(run):
    s = report.write(run)
    t = _tickets(run)
    assert [x["issue_id"] for x in t] == ["i-d", "i-l", "i-m", "i-q"]
    assert [x["rank"] for x in t] == [1, 2, 3, 4]
    # confirmed 1.0 * high 0.8 * default reach 0.6 * dast-supported runtime 1.0
    assert t[0]["score"] == 0.48 and t[0]["verdict"] == "confirmed"
    # likely 0.7 * 0.8 * 0.6 * 0.8 ; needs_review 0.4 * 0.8 * 0.6 * 0.8
    assert t[1]["score"] == 0.269 and t[2]["score"] == 0.154
    assert t[0]["members"] == ["POL-d"] and t[0]["location"] == "a.ts:1"
    assert {e["id"] for e in t[1]["evidence"]} >= {"e1", "e2"}
    assert all(set(e) == {"id", "type", "stance", "method"} for x in t for e in x["evidence"])
    # i-q: a model-only non_security suggestion is routed to review, so it stays open as needs_review
    assert t[3]["verdict"] == "needs_review" and t[3]["route"] == "review" and t[3]["score"] > 0
    assert s["open"] == 4 and s["closed"] == 1


def test_weights():
    from fva.export.report import finding_score
    assert finding_score("not_applicable", "critical", [], frozenset()) == 0.0
    assert finding_score("confirmed", "critical", [], frozenset()) == 0.48  # 1*1*0.6*0.8


def test_closed_cite_evidence(run):
    report.write(run)
    md = (run / "report.md").read_text(encoding="utf-8")
    closed = md.split("## Closed")[1]
    assert "i-t" in closed and "e0" in closed and "i-q" not in closed
    assert "open, not auto-verified" in md.split("## Closed")[0]
    assert md.index("## Open issues") < md.index("## Closed")


def test_closed_without_evidence_raises(run, monkeypatch):
    from fva import triage
    real = triage.build
    monkeypatch.setattr(triage, "build", lambda *a, **k: [{**r, "evidence_ids": []} if r["verdict"] == "not_applicable"
                                                          else r for r in real(*a, **k)])
    with pytest.raises(ValueError):
        report.build(run)


def test_no_runtime_summary_leak(run):
    p = run / "evidence.jsonl"
    lines = [json.loads(x) for x in p.read_text().splitlines()]
    for d in lines:
        if d["evidence_id"] == "e4":
            d["summary"] = "RAWRECEIPT-SECRET"
            d["detail_ref"] = "receipts/RAWRECEIPT-DETAIL"
    p.write_text("\n".join(json.dumps(d) for d in lines) + "\n")
    report.write(run)
    for n in ("tickets.jsonl", "report.md", "report.html"):
        text = (run / n).read_text(encoding="utf-8")
        assert "RAWRECEIPT" not in text
    assert any(e["id"] == "e4" for e in _tickets(run)[0]["evidence"])


def test_byte_identical(run):
    report.write(run)
    first = [(run / n).read_bytes() for n in ("tickets.jsonl", "report.md", "report.html")]
    report.write(run)
    assert first == [(run / n).read_bytes() for n in ("tickets.jsonl", "report.md", "report.html")]


def test_every_open_ticket_shows_missing_evidence(run):
    report.write(run)
    md = (run / "report.md").read_text(encoding="utf-8")
    page = (run / "report.html").read_text(encoding="utf-8")
    assert "| Missing evidence |" in md
    for ticket in _tickets(run):
        assert ticket["missing_evidence"].strip()
        assert report._cell(ticket["missing_evidence"]) in md
        assert escape(ticket["missing_evidence"], quote=True) in page
        assert all(code in page for code in ticket["exceptions"])
    assert all("missing_evidence" not in issue for issue in report.build(run)[1])


def test_group_retains_nonprimary_open_members_gap(run):
    path = run / "findings.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        if row["finding_id"] == "m":
            row.update(issue_id="i-l", primary=False, disposition="dependency:unresolved_name", package="example@1")
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    ticket = next(t for t in report.build(run)[0] if t["issue_id"] == "i-l")
    assert "static and model evidence cannot confirm" in ticket["missing_evidence"]
    assert "package-name resolution" in ticket["missing_evidence"] and "example" in ticket["missing_evidence"]


def test_cli_report(run, capsys):
    cli.main(["report", str(run)])
    assert "'open': 4" in capsys.readouterr().out
    assert all((run / n).exists() for n in ("tickets.jsonl", "report.md", "report.html"))


def test_html_report_is_static_complete_and_excludes_private_fields(run):
    token = "FAKE-TOKEN-DO-NOT-PRINT"
    tenant = "FAKE-TENANT-DO-NOT-PRINT"
    evidence_path = run / "evidence.jsonl"
    evidence_rows = [json.loads(line) for line in evidence_path.read_text(encoding="utf-8").splitlines()]
    evidence_rows[0]["summary"] = f"{token} {tenant}"
    evidence_rows[0]["detail_ref"] = f"receipts/{token}"
    evidence_path.write_text("\n".join(json.dumps(row) for row in evidence_rows) + "\n", encoding="utf-8")
    (run / "summary.json").write_text(json.dumps({"profile": "p", "secret": token, "tenant_id": tenant}),
                                       encoding="utf-8")
    findings_path = run / "findings.jsonl"
    findings = [json.loads(line) for line in findings_path.read_text(encoding="utf-8").splitlines()]
    findings[0]["source_finding_id"] = "POL-<t&>"
    findings_path.write_text("\n".join(json.dumps(row) for row in findings) + "\n", encoding="utf-8")

    report.write(run)
    page = (run / "report.html").read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert "Raw findings: 5" in page
    assert "Closed issues</dt><dd>1" in page
    assert "Fix tickets (likely or confirmed)</dt><dd>2" in page
    assert "Needs review</dt><dd>2" in page
    assert "TEST_ONLY" in page and "e0 · deployment_boundary · refutes · m" in page
    assert all(finding["source_finding_id"] in page for finding in findings[1:])
    assert "POL-&lt;t&amp;&gt;" in page and "POL-<t&>" not in page
    assert not any(value in page for value in (token, tenant, "http://", "https://", "<script", "<link"))
