"""Every loader rejects malformed input with a ValueError naming the file, returns nothing, and leaves the input untouched."""
import json
from pathlib import Path

import pytest

from fva.adapters import mapping, poc_ledger, polaris, sarif
from fva.pipeline import load_findings

FIX = Path(__file__).parent / "fixtures"


def _lines(name):
    return (FIX / name).read_text(encoding="utf-8").splitlines()


def _put(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def _ledger_rows():
    rows = []
    for line in _lines("polaris_sample.jsonl")[:3]:
        r = json.loads(line)
        r.update(classification="test_only", disposition="not_applicable", confidence="high", evidence="synthetic")
        rows.append(r)
    return rows


def _mapping_load(p):
    return mapping.load(p, polaris.POLARIS)


def _first():
    return json.loads(_lines("polaris_sample.jsonl")[0])


JSONL_CASES = {
    "truncated": lambda: _lines("polaris_sample.jsonl")[0][:-40],
    "bad_line_in_middle": lambda: "\n".join([_lines("polaris_sample.jsonl")[0], "{not json", _lines("polaris_sample.jsonl")[1]]),
    "non_object_line": lambda: "\n".join([_lines("polaris_sample.jsonl")[0], "[1, 2]"]),
    "missing_id": lambda: "\n".join([_lines("polaris_sample.jsonl")[0], json.dumps({"tool": "SAST", "checker": "x"})]),
    "bad_line_number": lambda: "\n".join([_lines("polaris_sample.jsonl")[0], json.dumps({**_first(), "line": "abc"})]),
}


@pytest.mark.parametrize("loader", [polaris.load, _mapping_load, poc_ledger.load], ids=["polaris", "mapping", "poc_ledger"])
@pytest.mark.parametrize("case", sorted(JSONL_CASES))
def test_flat_jsonl(tmp_path, loader, case):
    p = _put(tmp_path, "in.jsonl", JSONL_CASES[case]())
    before = p.read_bytes()
    with pytest.raises(ValueError, match="in.jsonl") as e:
        loader(p)
    if case != "truncated":
        assert "L2" in str(e.value)
    assert p.read_bytes() == before


def test_valid_jsonl_still_loads(tmp_path):
    p = _put(tmp_path, "in.jsonl", "\n".join(_lines("polaris_sample.jsonl")))
    assert polaris.load(p)[1]


def test_empty_jsonl_is_zero_findings(tmp_path):
    p = _put(tmp_path, "in.jsonl", "")
    assert polaris.load(p)[1] == []


@pytest.mark.parametrize("case", ["missing_classification", "unknown_classification", "missing_disposition"])
def test_poc_ledger_rows(tmp_path, case):
    rows = _ledger_rows()
    if case == "missing_classification":
        del rows[1]["classification"]
    elif case == "unknown_classification":
        rows[1]["classification"] = "nope"
    else:
        del rows[1]["disposition"]
    p = _put(tmp_path, "ledger.jsonl", "\n".join(json.dumps(r) for r in rows))
    before = p.read_bytes()
    with pytest.raises(ValueError, match="ledger.jsonl"):
        poc_ledger.load(p)
    assert p.read_bytes() == before


def test_poc_ledger_valid_synthetic(tmp_path):
    p = _put(tmp_path, "ledger.jsonl", "\n".join(json.dumps(r) for r in _ledger_rows()))
    _, findings, evidence, verdicts = poc_ledger.load(p)
    assert len(findings) == len(evidence) == len(verdicts) == 2


def _array():
    return json.dumps([json.loads(line) for line in _lines("polaris_sample.jsonl")])


JSON_CASES = {
    "empty": lambda: "",
    "invalid": lambda: _array()[:-1] + "!",
    "truncated": lambda: _array()[: len(_array()) // 2],
    "scalar": lambda: "42",
    "object_without_list": lambda: json.dumps({"a": 1}),
    "non_object_row": lambda: json.dumps([_first(), 7]),
    "missing_id": lambda: json.dumps([_first(), {"tool": "SAST"}]),
}


@pytest.mark.parametrize("loader", [polaris.load, _mapping_load], ids=["polaris", "mapping"])
@pytest.mark.parametrize("case", sorted(JSON_CASES))
def test_flat_json(tmp_path, loader, case):
    p = _put(tmp_path, "in.json", JSON_CASES[case]())
    before = p.read_bytes()
    with pytest.raises(ValueError, match="in.json"):
        loader(p)
    assert p.read_bytes() == before


CSV_HEAD = "Issue ID,Rule,Name,Sev,Kind,File,Line,CWE\n"
CSV_CASES = {
    "missing_id_column": "Rule,Name\nR1,x\n",
    "short_row": CSV_HEAD + "ID-1,R1,Weak hash,Low,sast,a.py,1,CWE-1\nID-2,R2,Deb",
    "bad_kind": CSV_HEAD + "ID-1,R1,x,Low,bogus,a.py,1,\n",
    "blank_id": CSV_HEAD + ",R1,x,Low,sast,a.py,1,\n",
}
CSV_MAP = mapping.FieldMap(source_tool="generic", id="Issue ID", rule_id="Rule", title="Name", severity="Sev",
                           finding_type="Kind", path="File", line="Line", cwe="CWE")


@pytest.mark.parametrize("case", sorted(CSV_CASES))
def test_csv(tmp_path, case):
    p = _put(tmp_path, "in.csv", CSV_CASES[case])
    before = p.read_bytes()
    with pytest.raises(ValueError, match="in.csv"):
        mapping.load(p, CSV_MAP)
    assert p.read_bytes() == before


def test_csv_fixture_valid_with_map():
    assert len(mapping.load(FIX / "generic.csv", CSV_MAP)[1]) == 2


def _sarif_mut(fn):
    doc = json.loads((FIX / "sample.sarif.json").read_text(encoding="utf-8"))
    fn(doc)
    return json.dumps(doc)


SARIF_CASES = {
    "empty": lambda: "",
    "invalid": lambda: "{nope",
    "truncated": lambda: (FIX / "sample.sarif.json").read_text(encoding="utf-8")[:200],
    "list_top_level": lambda: "[]",
    "empty_object": lambda: "{}",
    "bad_version": lambda: _sarif_mut(lambda d: d.update(version="1.0.0")),
    "missing_version": lambda: _sarif_mut(lambda d: d.pop("version")),
    "no_runs": lambda: _sarif_mut(lambda d: d.pop("runs")),
    "runs_not_list": lambda: _sarif_mut(lambda d: d.update(runs={})),
    "run_not_object": lambda: _sarif_mut(lambda d: d.update(runs=[1])),
    "results_not_list": lambda: _sarif_mut(lambda d: d["runs"][0].update(results={})),
    "result_not_object": lambda: _sarif_mut(lambda d: d["runs"][0]["results"].append("x")),
}


@pytest.mark.parametrize("case", sorted(SARIF_CASES))
def test_sarif(tmp_path, case):
    p = _put(tmp_path, "in.sarif.json", SARIF_CASES[case]())
    before = p.read_bytes()
    with pytest.raises(ValueError, match="in.sarif.json"):
        sarif.parse(p)
    assert p.read_bytes() == before


def _mcp(name):
    return (FIX / name).read_text(encoding="utf-8")


def _issues(name):
    return polaris._unwrap(json.loads(_mcp(name)))


MCP_CASES = {
    "empty": lambda n: "",
    "invalid": lambda n: "{nope",
    "truncated": lambda n: _mcp(n)[: len(_mcp(n)) // 2],
    "scalar": lambda n: "42",
    "string": lambda n: '"x"',
    "non_object_issue": lambda n: json.dumps([_issues(n)[0], 3]),
    "issue_missing_id": lambda n: json.dumps([_issues(n)[0], {k: v for k, v in _issues(n)[0].items() if k != "id"}]),
    "bad_content_envelope": lambda n: json.dumps({"content": [{"type": "text", "text": "{broken"}]}),
    "empty_content": lambda n: json.dumps({"content": []}),
}


@pytest.mark.parametrize("loader", [polaris.load_mcp, polaris.load_dast], ids=["mcp", "dast"])
@pytest.mark.parametrize("fixture", ["polaris_mcp_sast.json", "polaris_mcp_sca.json", "polaris_mcp_dast.json"])
@pytest.mark.parametrize("case", sorted(MCP_CASES))
def test_mcp(tmp_path, loader, fixture, case):
    p = _put(tmp_path, "in.json", MCP_CASES[case](fixture))
    before = p.read_bytes()
    with pytest.raises(ValueError, match="in.json"):
        loader(p)
    assert p.read_bytes() == before


def test_mcp_bad_file_among_good_ones_yields_nothing(tmp_path):
    good = _put(tmp_path, "a.json", _mcp("polaris_mcp_sast.json"))
    bad = _put(tmp_path, "b.json", "{nope")
    with pytest.raises(ValueError, match="b.json"):
        polaris.load_mcp([good, bad])


@pytest.mark.parametrize("name,content", [("in.jsonl", "{bad"), ("in.csv", "Rule\nR1\n"), ("in.json", "{bad")])
def test_load_findings_passes_errors_through(tmp_path, name, content):
    p = _put(tmp_path, name, content)
    with pytest.raises(ValueError, match=r"in\."):
        load_findings(str(p))
