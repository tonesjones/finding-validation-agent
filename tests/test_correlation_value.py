import json
from pathlib import Path

import pytest

from fva.analysis import correlation_value as cv

FIX = Path(__file__).parent / "fixtures"
ZERO = "0" * 32


def _r(sid, tool, **kw):
    base = {"sid": sid, "tool": tool, "cwe": set(), "path": None, "line": None, "function": None, "package": None,
            "advisory": None, "linked": None, "md5": None, "tech": None, "risk": None, "severity": "high",
            "type_family": None, "reachability": None}
    return {**base, **kw}


RECS = [
    _r("SID-S1", "sast", cwe={"CWE-89"}, path="p1", line=10, function="fA", md5="m1", risk=80),
    _r("SID-S2", "sast", cwe={"CWE-89"}, path="p1", line=10, function="fB", md5="m1", risk=65),
    _r("SID-S3", "sast", cwe={"CWE-89", "CWE-79"}, path="p2", line=5, function="fA", md5=ZERO, severity="low"),
    _r("SID-S4", "sast", cwe={"CWE-79"}, path="p3", line=7, function="unknown", md5=ZERO, risk=20, severity="low"),
    _r("SID-C1", "sca", cwe={"CWE-89"}, package=("a", "1"), advisory="CVE-1", linked="BDSA-1", reachability="REACHABLE"),
    _r("SID-C2", "sca", cwe={"CWE-79"}, package=("a", "1"), advisory="CVE-2", linked="BDSA-2", reachability="UNDETERMINED"),
    _r("SID-C3", "sca", package=("b", "1"), advisory="BDSA-1"),
    _r("SID-C4", "sca", cwe={"CWE-89"}, package=("c", "1"), linked="BDSA-1"),  # not in key
    _r("SID-D1", "dast"),
]
KEY = {sid: {"verdict": v} for sid, v in {
    "SID-S1": "confirmed", "SID-S2": "likely", "SID-S3": "not_applicable", "SID-S4": "valid_non_security",
    "SID-C1": "needs_review", "SID-C2": "not_applicable", "SID-C3": "confirmed"}.items()}


@pytest.fixture(scope="module")
def res():
    return cv.analyze(RECS, KEY)


def test_meta(res):
    m = res["meta"]
    assert (m["dast_ignored"], m["sast"], m["sca"]) == (1, 4, 4)
    assert m["scored_sast"] == {"n": 4, "real": 2, "cleared": 2} and m["scored_sca"] == {"n": 3, "real": 2, "cleared": 1}


def test_same_cwe(res):
    k = res["keys"]["same_cwe"]  # (S1,C1) (S2,C1) (S3,C1) (S3,C2) (S4,C2); C4 unscored
    assert (k["pairs"], k["findings_covered"]) == (5, 6)
    assert k["coverage"] == pytest.approx(6 / 7, abs=1e-4) and k["mean_fanout"] == pytest.approx(10 / 6, abs=1e-4)
    assert k["coherence"] == 0.8 and k["verdict_agreement"] == 0.2
    assert k["n_cond"] == 5 and k["lift"] == pytest.approx(4 / (2 * 2 / 3 + 3 * 0.5), abs=1e-4)


def test_same_path_line(res):
    k = res["keys"]["same_path_line"]
    assert (k["pairs"], k["coverage"], k["mean_fanout"], k["coherence"]) == (1, 0.5, 1.0, 1.0)
    assert (k["n_cond"], k["lift"]) == (2, 2.0)


def test_same_fragment_md5_ignores_zeros(res):
    k = res["keys"]["same_fragment_md5"]  # S3/S4 share an all-zero md5 that must not pair
    assert (k["pairs"], k["findings_covered"], k["coherence"], k["lift"]) == (1, 2, 1.0, 2.0)


def test_same_function_ignores_unknown(res):
    k = res["keys"]["same_function"]  # S1/S3 share fA (real, cleared)
    assert (k["pairs"], k["coherence"], k["n_cond"], k["lift"]) == (1, 0.0, 1, 0.0)


def test_cve_bdsa_alias(res):
    k = res["keys"]["cve_bdsa_alias"]  # C1.linked == C3.advisory; C4 unscored
    assert (k["pairs"], k["findings_covered"], k["mean_fanout"], k["coherence"]) == (1, 2, 1.0, 1.0)
    assert k["coverage"] == pytest.approx(2 / 3, abs=1e-4) and k["lift"] == 1.5


def test_same_component_version(res):
    k = res["keys"]["same_component_version"]  # C1/C2 share (a, 1)
    assert (k["pairs"], k["coherence"]) == (1, 0.0)


def test_source_keys_skipped_without_source(res):
    for n in ("shipped_import_same_file", "advisory_symbol_near_sink"):
        assert res["keys"][n] == {"skipped": "needs --source"}


def test_signal_tables(res):
    s = res["signals"]
    assert s["sca_reachability"]["REACHABLE"] == {"n": 1, "real": 1, "cleared": 0, "real_rate": 1.0}
    assert s["sca_reachability"]["UNDETERMINED"]["cleared"] == 1 and s["sca_reachability"]["none"]["real"] == 1
    rs = s["risk_score"]["sast"]
    assert {b: (v["real"], v["cleared"]) for b, v in rs.items()} == {
        ">=80": (1, 0), "60-79": (1, 0), "<40": (0, 1), "none": (0, 1)}
    assert s["risk_score"]["sca"]["none"]["n"] == 3
    assert (s["severity"]["sast"]["high"]["real"], s["severity"]["sast"]["low"]["cleared"]) == (2, 2)


def test_no_sids_in_outputs(res):
    for text in (cv.to_markdown(res), json.dumps(res)):
        assert "SID-" not in text and "CVE-" not in text and "BDSA" not in text
    md = cv.to_markdown(res)
    assert "same_cwe" in md and "lift" in md and "needs --source" in md


class _Idx:
    def __init__(self, files):
        self.files = files

    def resolve(self, p):
        return (p, "exact") if p in self.files else (None, "path_missing")

    def lines(self, p):
        return self.files[p]


def test_source_keys_with_stub_source(monkeypatch):
    from fva.correlation import package_link
    pad = lambda at, word: [word if i == at else "x" for i in range(60)]
    idx = _Idx({"p1": pad(20, "busboy.on"), "p2": pad(40, "busboy.on")})
    recs = [_r("a", "sast", path="p1", line=10), _r("b", "sast", path="p2", line=10),
            _r("x", "sca", tech="the `busboy` handler in lib/make-middleware.js")]
    key = {s: {"verdict": "confirmed"} for s in "abx"}
    monkeypatch.setattr(package_link, "link", lambda sca, sast, g, p: True if sast == "b" else None)
    src = {"idx": idx, "graph": None, "profile": None, "findings": {s: s for s in "abx"}}
    res = cv.analyze(recs, key, source=src)
    near, ship = res["keys"]["advisory_symbol_near_sink"], res["keys"]["shipped_import_same_file"]
    assert (near["pairs"], near["coverage"]) == (1, round(2 / 3, 4))
    assert ship["pairs"] == 1 and ship["findings_covered"] == 2


def test_load_records_from_fixtures():
    recs = {r["tool"]: r for r in cv.load_records([FIX / "polaris_mcp_sast.json", FIX / "polaris_mcp_sca.json"])}
    sast, sca = recs["sast"], recs["sca"]
    assert sast["md5"] == ZERO and sast["cwe"] == {"CWE-89"} and sast["line"] == 34 and sast["risk"] == 80
    assert sast["type_family"] == "sigma.sqli" and sast["reachability"] is None
    assert sca["linked"] == "BDSA-2023-4469" and sca["reachability"] == "REACHABLE"
    assert "make-middleware.js" in sca["tech"] and sca["package"] == ("multer", "1.4.5-lts.1")
    assert sca["advisory"] == "CVE-2025-48997" and sca["risk"] == 65
    assert "make-middleware.js" in cv._idents(sca["tech"])


def test_main_requires_key(tmp_path):
    with pytest.raises(SystemExit, match="answer key not found"):
        cv.main(["--key", str(tmp_path / "nope.jsonl"), "--out", str(tmp_path)])


def test_main_end_to_end(tmp_path, capsys):
    key = tmp_path / "key.jsonl"
    key.write_text("\n".join(json.dumps({"candidate_id": i, "classification": c}) for i, c in (
        ("AAAA1111BBBB2222CCCC3333DDDD4444", "true_positive_runtime_validated"),
        ("EEEE5555FFFF6666AAAA7777BBBB8888", "test_only"))), encoding="utf-8")
    out = tmp_path / "out"
    cv.main(["--findings", str(FIX / "polaris_mcp_s*.json"), "--key", str(key), "--out", str(out)])
    res = json.loads((out / "correlation-value.json").read_text(encoding="utf-8"))
    assert res["meta"]["scored_sast"]["real"] == 1 and res["meta"]["scored_sca"]["cleared"] == 1
    assert res["keys"]["same_cwe"]["pairs"] == 0 and (out / "correlation-value.md").exists()
    text = (out / "correlation-value.md").read_text(encoding="utf-8") + json.dumps(res) + capsys.readouterr().out
    assert "AAAA1111" not in text and "multer" not in text and "login.ts" not in text
