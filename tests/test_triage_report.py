import json

from fva import __main__ as cli, triage
from fva.export import triage_report
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q)


def test_write_outputs(run):
    s = triage_report.write(run)
    rows = [json.loads(x) for x in (run / "triage.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["finding_id"] for r in rows] == [r["finding_id"] for r in triage.build(run)]
    assert s["rows"] == len(rows) == 5
    assert s["auto"] + s["review"] == s["rows"]
    assert s["review"] == sum(r["route"] == "review" for r in rows)
    assert s["by_exception"] == {e: sum(e in r["exceptions"] for r in rows) for e in triage.EXCEPTIONS
                                 if any(e in r["exceptions"] for r in rows)}
    md = (run / "triage.md").read_text(encoding="utf-8")
    assert md.startswith("# Triage") and "## Exception list" in md and "Findings: 5" in md


def test_write_is_byte_identical(run):
    triage_report.write(run)
    first = [(run / n).read_bytes() for n in ("triage.jsonl", "triage.md")]
    triage_report.write(run)
    assert first == [(run / n).read_bytes() for n in ("triage.jsonl", "triage.md")]


def test_cli_triage(run, capsys):
    cli.main(["triage", str(run)])
    assert "'rows': 5" in capsys.readouterr().out
    assert (run / "triage.jsonl").exists() and (run / "triage.md").exists()
