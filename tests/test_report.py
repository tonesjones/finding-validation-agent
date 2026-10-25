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
    # likely 0.7 * 0.8 * entrypoint reach 1.0 * 0.8 ; needs_review 0.4 * 0.8 * 0.6 * 0.8
    assert t[1]["score"] == 0.448 and t[2]["score"] == 0.154
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


def test_tickets_and_reports_name_the_advisory(tmp_path):
    """Two advisories on one package version stay apart: each ticket names its own CVE."""
    from tests.test_worksheet import _row
    rows = [{**_row(fid, "sca", "assess"), "path": None, "line": None, "package": "php@8.4.26", "cwe": [],
             "title": "PHP Vulnerable to RCE", "advisory": cve, "linked_advisories": linked}
            for fid, cve, linked in (("a", "CVE-2099-0001", ["BDSA-2099-0001"]), ("b", "CVE-2099-0002", []))]
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p"}))
    report.write(tmp_path)
    t = {x["issue_id"]: x for x in _tickets(tmp_path)}
    assert t["i-a"]["advisory"] == "CVE-2099-0001" and t["i-a"]["linked_advisories"] == ["BDSA-2099-0001"]
    assert t["i-b"]["advisory"] == "CVE-2099-0002" and t["i-b"]["linked_advisories"] == []
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "| CVE-2099-0001, BDSA-2099-0001 | PHP Vulnerable to RCE |" in md
    assert "| CVE-2099-0002 | PHP Vulnerable to RCE |" in md
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "CVE-2099-0001, BDSA-2099-0001 · PHP Vulnerable to RCE</h4>" in page


def test_ticket_without_advisory(run):
    """Rows from runs made before the advisory field, and SAST rows, carry none."""
    report.write(run)
    assert all(x["advisory"] is None and x["linked_advisories"] == [] for x in _tickets(run))


def test_empty_run_writes_empty_outputs(tmp_path):
    from fva.export import triage_report
    (tmp_path / "findings.jsonl").write_text("")
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p", "status": "complete"}))
    assert triage_report.write(tmp_path)["rows"] == 0
    assert report.write(tmp_path) == {"open": 0, "closed": 0, "by_verdict": {}}
    assert (tmp_path / "triage.jsonl").read_text() == "" and (tmp_path / "tickets.jsonl").read_text() == ""
    assert "Open issues: 0" in (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Raw findings: 0" in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_missing_findings_file_still_fails(tmp_path):
    with pytest.raises(SystemExit, match="findings.jsonl missing"):
        report.build(tmp_path)
