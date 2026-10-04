import json

import pytest

from fva import __main__ as cli
from fva.export import report
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q; one issue each)


def _tickets(run):
    return [json.loads(x) for x in (run / "tickets.jsonl").read_text(encoding="utf-8").splitlines()]


def test_ranking_and_score_math(run):
    s = report.write(run)
    t = _tickets(run)
    assert [x["issue_id"] for x in t] == ["i-d", "i-l", "i-m"]
    assert [x["rank"] for x in t] == [1, 2, 3]
    # confirmed 1.0 * high 0.8 * default reach 0.6 * dast-supported runtime 1.0
    assert t[0]["score"] == 0.48 and t[0]["verdict"] == "confirmed"
    # likely 0.7 * 0.8 * 0.6 * 0.8 ; needs_review 0.4 * 0.8 * 0.6 * 0.8
    assert t[1]["score"] == 0.269 and t[2]["score"] == 0.154
    assert t[0]["members"] == ["POL-d"] and t[0]["location"] == "a.ts:1"
    assert {e["id"] for e in t[1]["evidence"]} >= {"e1", "e2"}
    assert all(set(e) == {"id", "type", "stance", "method"} for x in t for e in x["evidence"])
    assert s["open"] == 3 and s["closed"] == 2


def test_weights():
    from fva.export.report import finding_score
    assert finding_score("not_applicable", "critical", [], frozenset()) == 0.0
    assert finding_score("confirmed", "critical", [], frozenset()) == 0.48  # 1*1*0.6*0.8


def test_closed_cite_evidence(run):
    report.write(run)
    md = (run / "report.md").read_text(encoding="utf-8")
    closed = md.split("## Closed")[1]
    assert "i-t" in closed and "e0" in closed and "i-q" in closed and "e5" in closed
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
    for n in ("tickets.jsonl", "report.md"):
        text = (run / n).read_text(encoding="utf-8")
        assert "RAWRECEIPT" not in text
    assert any(e["id"] == "e4" for e in _tickets(run)[0]["evidence"])


def test_byte_identical(run):
    report.write(run)
    first = [(run / n).read_bytes() for n in ("tickets.jsonl", "report.md")]
    report.write(run)
    assert first == [(run / n).read_bytes() for n in ("tickets.jsonl", "report.md")]


def test_cli_report(run, capsys):
    cli.main(["report", str(run)])
    assert "'open': 3" in capsys.readouterr().out
    assert (run / "tickets.jsonl").exists() and (run / "report.md").exists()
