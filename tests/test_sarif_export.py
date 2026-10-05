import json

from fva import __main__ as cli
from fva.adapters import sarif as sarif_adapter
from fva.export import sarif_export
from tests.test_worksheet import _row, run  # noqa: F401  (fixture: findings t,l,m,d,q)

FILES = ("sast.sarif", "sca.sarif")


def _load(run, name):
    return json.loads((run / name).read_text(encoding="utf-8"))


def _results(doc):
    return doc["runs"][0]["results"]


def _add(run, row):
    rows = [json.loads(x) for x in (run / "findings.jsonl").read_text().splitlines()]
    rows.append(row)
    (run / "findings.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n")


def _add_sca(run):
    r = _row("s", "sca", "assess")
    r.update(package="lodash@4.17.0", path=None, line=None)
    _add(run, r)


def test_round_trip_ids(run):
    _add_sca(run)
    sarif_export.write(run)
    assert not (run / "dast.sarif").exists()
    seen = []
    for n in FILES:
        doc = _load(run, n)
        assert doc["version"] == "2.1.0" and "$schema" in doc and doc["runs"][0]["tool"]["driver"]["name"]
        _, fs = sarif_adapter.parse(run / n)
        ids = [f.source_finding_id for f in fs]
        assert ids == [r["guid"] for r in _results(doc)]
        assert not any(f.source_finding_id_synthesized for f in fs)
        seen += ids
    assert sorted(seen) == ["POL-d", "POL-l", "POL-m", "POL-q", "POL-s", "POL-t"]
    assert [r["guid"] for r in _results(_load(run, "sca.sarif"))] == ["POL-s"]


def test_effective_verdict_and_fields(run):
    sarif_export.write(run)
    by = {r["guid"]: r for r in _results(_load(run, "sast.sarif"))}
    assert by["POL-t"]["properties"]["fva"]["verdict"] == "not_applicable"
    assert by["POL-t"]["properties"]["fva"]["reason_codes"] == ["TEST_ONLY"]
    assert by["POL-d"]["properties"]["fva"]["verdict"] == "confirmed"
    # a model-only non_security closure is not auto-routed, so it is reported as open
    q = by["POL-q"]["properties"]["fva"]
    assert q["route"] == "review" and q["verdict"] == "needs_review" and q["issue_id"] == "i-q"
    assert all(set(e) == {"id", "type", "stance", "method"} for r in by.values()
               for e in r["properties"]["fva"]["evidence"])
    assert by["POL-l"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_byte_identical(run):
    _add_sca(run)
    sarif_export.write(run)
    first = [(run / n).read_bytes() for n in FILES]
    sarif_export.write(run)
    assert first == [(run / n).read_bytes() for n in FILES]
    assert all(b"\r" not in x for x in first)


def test_no_summary_leak(run):
    p = run / "evidence.jsonl"
    lines = [json.loads(x) for x in p.read_text().splitlines()]
    for d in lines:
        d["summary"] = "RAWRECEIPT-SECRET"
        d["detail_ref"] = "receipts/RAWRECEIPT-DETAIL"
    p.write_text("\n".join(json.dumps(d) for d in lines) + "\n")
    sarif_export.write(run)
    for n in FILES:
        assert "RAWRECEIPT" not in (run / n).read_text(encoding="utf-8")


def test_dast_only_when_present(run):
    sarif_export.write(run)
    assert not (run / "dast.sarif").exists()
    r = _row("x", "dast", "runtime_only")
    r.update(path=None, line=None, endpoint="GET /rest/x")
    _add(run, r)
    sarif_export.write(run)
    assert [x["guid"] for x in _results(_load(run, "dast.sarif"))] == ["POL-x"]


def test_cli(run, capsys):
    cli.main(["sarif", str(run)])
    assert "'sast': 5" in capsys.readouterr().out
    assert (run / "sast.sarif").exists()
