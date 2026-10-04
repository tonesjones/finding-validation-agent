import json
import os
import shutil
import subprocess

import pytest

from fva import loaded_packages as lp
from fva.correlation.source_pin import pin
from fva.runtime import digest, read_rows
from tests.test_worksheet import _row

PACKAGES = {"pkg-a": ("1.0.0", "module.exports = require('@sc/pkg-d');", "index.js"),
            "pkg-b": ("2.0.0", "export default 2;", "index.js"),  # ESM, imported dynamically
            "pkg-c": ("3.0.0", "module.exports = 3;", "index.js"),  # installed, never loaded
            "pkg-a/node_modules/@sc/pkg-d": ("4.0.0", "module.exports = 4;", "index.js")}


def _package(root, rel, version, body, main):
    d = root / "node_modules" / rel
    d.mkdir(parents=True)
    name = rel.rsplit("node_modules/", 1)[-1]
    meta = {"name": name, "version": version, "main": main}
    if rel == "pkg-b":
        meta |= {"type": "module", "exports": "./index.js"}
    (d / "package.json").write_text(json.dumps(meta))
    (d / main).write_text(body)
    return d


@pytest.fixture
def app(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.js").write_text("require('pkg-a');\nimport('pkg-b');\n")
    for rel, (version, body, main) in PACKAGES.items():
        _package(src, rel, version, body, main)
    run = tmp_path / "run"
    run.mkdir()
    rows = [_row(fid, "sca", "assess") | {"package": pkg} for fid, pkg in (
        ("a", "pkg-a@1.0.0"), ("b", "pkg-b@2.0.0"), ("c", "pkg-c@3.0.0"), ("d", "@sc/pkg-d@4.0.0"),
        ("e", "pkg-e@5.0.0"), ("a9", "pkg-a@0.9.0"))] + [_row("s", "sast", "assess")]
    (run / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (run / "summary.json").write_text(json.dumps({"profile": "p", "source_content_sha256": pin(src).content_sha256}))
    (run / "evidence.jsonl").write_text("")
    return src, run


def _raw(dir_, files, hooks=True, tail=""):
    dir_.mkdir(exist_ok=True)
    head = json.dumps({"format": lp.RAW_FORMAT, "node": "v24.0.0", "hooks": hooks})
    n = len(list(dir_.glob("*")))
    (dir_ / f"loaded-{n}.jsonl").write_text("\n".join([head, *map(json.dumps, map(str, files))]) + "\n" + tail)
    return dir_


def _loaded(src):
    return [src / "app.js", src / "node_modules/pkg-a/index.js", src / "node_modules/pkg-b/index.js",
            src / "node_modules/pkg-a/node_modules/@sc/pkg-d/index.js"]


def _observed(receipt):
    return {o["subject"]["name"] + "@" + o["subject"]["version"]: (o["observed"], o["finding_ids"])
            for o in receipt["observations"]}


def test_receipt_maps_loaded_files_to_packages(app, tmp_path):
    src, run = app
    elsewhere = tmp_path / "other" / "node_modules" / "pkg-c" / "index.js"  # same name, outside the source
    receipt = lp.build_receipt(run, _raw(tmp_path / "raw", [*_loaded(src), elsewhere]), src, "npm test")
    assert _observed(receipt) == {"pkg-a@1.0.0": (True, ["a"]), "pkg-b@2.0.0": (True, ["b"]),
                                  "@sc/pkg-d@4.0.0": (True, ["d"]), "pkg-c@3.0.0": (False, ["c"])}
    assert receipt["collector"] == lp.COLLECTOR and receipt["exercise"] == "npm test"


@pytest.mark.parametrize("raw", [{"hooks": False}, {"tail": '"C:\\\\half'}])
def test_absence_needs_complete_records(app, tmp_path, raw):
    src, run = app
    receipt = lp.build_receipt(run, _raw(tmp_path / "raw", _loaded(src), **raw), src, "npm test")
    assert "pkg-c@3.0.0" not in _observed(receipt)  # installed but never loaded: no record at all
    assert all(o["observed"] for o in receipt["observations"])


def test_one_incomplete_process_disables_absence(app, tmp_path):
    src, run = app
    raw = _raw(tmp_path / "raw", _loaded(src))
    _raw(raw, [], hooks=False)
    assert "pkg-c@3.0.0" not in _observed(lp.build_receipt(run, raw, src, "npm test"))


def test_source_must_match_run(app, tmp_path):
    src, run = app
    (src / "app.js").write_text("// changed\n")
    with pytest.raises(ValueError, match="source does not match"):
        lp.build_receipt(run, _raw(tmp_path / "raw", _loaded(src)), src, "npm test")


def test_no_records(app, tmp_path):
    src, run = app
    (tmp_path / "raw").mkdir()
    with pytest.raises(ValueError, match="no loaded-module records"):
        lp.build_receipt(run, tmp_path / "raw", src, "npm test")


def _write(receipt, path):
    path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return path


def test_import_verifies_and_appends(app, tmp_path):
    src, run = app
    raw = _raw(tmp_path / "raw", _loaded(src))
    receipt = lp.build_receipt(run, raw, src, "npm test")
    path = _write(receipt, tmp_path / "receipt.json")
    out = tmp_path / "derived"
    result = lp.main(["import", str(run), str(path), "--raw", str(raw), "--source", str(src), "--out", str(out)])
    assert result["records"] == 4 and result["receipt_sha256"] == digest(receipt)
    evs = {r["finding_ids"][0]: r for r in read_rows(out / "evidence.jsonl")}
    assert evs["c"]["stance"] == "refutes" and evs["a"]["stance"] == "neutral"
    assert (out / "observations" / f"{digest(receipt)}.json").exists()
    assert json.loads((out / "summary.json").read_text())["runtime_observations"][0]["records"] == 4
    assert (run / "evidence.jsonl").read_text() == ""  # base run untouched
    with pytest.raises(ValueError, match="already imported"):
        lp.main(["import", str(out), str(path), "--raw", str(raw), "--source", str(src),
                 "--out", str(tmp_path / "again")])


@pytest.mark.parametrize("tamper, match", [
    ("observed", "does not match its raw"),
    ("raw", "does not match its raw"),
    ("format", "content hash"),
])
def test_import_rejects_tampering(app, tmp_path, tamper, match):
    src, run = app
    raw = _raw(tmp_path / "raw", _loaded(src))
    receipt = lp.build_receipt(run, raw, src, "npm test")
    path = _write(receipt, tmp_path / "receipt.json")
    if tamper == "observed":
        receipt["observations"][-1]["observed"] = True
        _write(receipt, path)
    elif tamper == "raw":
        _raw(raw, [src / "node_modules/pkg-c/index.js"])
    else:
        path.write_text(json.dumps(receipt, indent=2))
    with pytest.raises(ValueError, match=match):
        lp.main(["import", str(run), str(path), "--raw", str(raw), "--source", str(src),
                 "--out", str(tmp_path / "derived")])
    assert not (tmp_path / "derived").exists()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_preload_with_node(app, tmp_path):
    src, run = app
    raw = tmp_path / "raw"
    env = {**os.environ, "FVA_LOADED_MODULES_DIR": str(raw)}
    subprocess.run(["node", "--require", str(lp.PRELOAD), "app.js"], cwd=src, env=env, check=True, timeout=60)
    receipt = lp.build_receipt(run, raw, src, "startup only")
    hooks = json.loads((next(raw.glob("loaded-*.jsonl"))).read_text().splitlines()[0])["hooks"]
    seen = _observed(receipt)
    assert seen["pkg-a@1.0.0"][0] and seen["@sc/pkg-d@4.0.0"][0]
    if hooks:
        assert seen["pkg-b@2.0.0"][0] and seen["pkg-c@3.0.0"] == (False, ["c"])
    else:  # older Node: ESM loads unseen, so no absence is recorded
        assert "pkg-c@3.0.0" not in seen
