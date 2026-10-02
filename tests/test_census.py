import json
import shutil
from pathlib import Path

from fva.analysis import census as cs

FIX = Path(__file__).parent / "fixtures"
NAMES = ["polaris_mcp_sast.json", "polaris_mcp_sca.json", "polaris_mcp_dast.json"]
LEAKS = ["FAKE", "juice.internal", "polaris.invalid", "TENANT", "Bearer", "SQLITE_ERROR", "Multer is vulnerable"]


def _c():
    return cs.census([FIX / n for n in NAMES])


def test_tool_types_and_counts():
    c = _c()
    tools = {k for k in c if k != "dropped"}
    assert tools == {"sast", "sca", "dast"}
    assert all(c[t]["issues"] == 1 for t in tools)


def test_enum_values_shown():
    assert _c()["sast"]["occurrence"]["cwe"]["values"] == {"CWE-89": 1}
    assert _c()["dast"]["top_level"]["context.toolType"]["values"] == {"dast": 1}


def test_no_leaks():
    c = _c()
    text = json.dumps(c) + cs.to_markdown(c)
    for bad in LEAKS:
        assert bad not in text, bad
    assert "values" not in c["sca"]["occurrence"]["description"]


def test_dropped():
    d = _c()["dropped"]
    assert {"technical-description", "linked-vulnerability-id"} <= set(d["sca"]["occurrence"])
    assert all("cwe" not in v["occurrence"] for v in d.values())
    assert "_type" in d["sast"]["top_level"]


def test_main_writes_files(tmp_path, capsys):
    src, out = tmp_path / "in", tmp_path / "out"
    src.mkdir()
    for n in NAMES:
        shutil.copy(FIX / n, src / n)
    (src / "types.json").write_text("{}")
    assert cs.main([str(src), "--out", str(out)]) == 0
    assert json.loads((out / "census.json").read_text())["sca"]["issues"] == 1
    assert "Dropped by adapter" in (out / "census.md").read_text()
    assert "sast=1" in capsys.readouterr().out
