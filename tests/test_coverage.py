"""Coverage import uses synthetic sources and findings only."""
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from fva import coverage, observations
from fva.correlation.source_pin import pin
from tests.test_worksheet import _row


FIXTURE = Path(__file__).parent / "fixtures" / "coverage-app"


@pytest.fixture
def prepared(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("covered.js", "missed.js"):
        shutil.copyfile(FIXTURE / name, source / name)
    (tmp_path / "outside.js").write_text("outside();\n", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    rows = [
        {"finding_id": "synthetic-covered", "finding_type": "sast", "path": ".\\covered.js", "line": 2},
        {"finding_id": "synthetic-missed", "finding_type": "sast", "path": "./missed.js", "line": 2},
        {"finding_id": "synthetic-outside", "finding_type": "sast", "path": "outside.js", "line": 1},
        {"finding_id": "synthetic-sca", "finding_type": "sca", "path": "covered.js", "line": 2},
    ]
    (run / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (run / "summary.json").write_text(json.dumps({"profile": "synthetic-profile",
                                                  "source_content_sha256": pin(source).content_sha256}),
                                      encoding="utf-8")
    return source, run


def test_istanbul_receipt_and_evidence_round_trip(prepared, tmp_path):
    source, run = prepared
    out = tmp_path / "receipt.json"
    coverage.main(["receipt", str(run), "--coverage", str(FIXTURE / "coverage-final.json"), "--source", str(source),
                   "--exercise", "synthetic tests", "--out", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    observations.Receipt.model_validate(data)
    assert [(o["finding_ids"][0], o["observed"], o["subject"]["path"])
            for o in data["observations"]] == [
                ("synthetic-covered", True, "covered.js"),
                ("synthetic-missed", False, "missed.js")]
    assert data["raw_file"]["sha256"] == hashlib.sha256((FIXTURE / "coverage-final.json").read_bytes()).hexdigest()
    evidence = observations.evidence_from_receipt(data, run)
    assert len(evidence) == 2
    assert all(e.tool_versions["kind"] == "line_executed" for e in evidence)
    assert all(e.stance.value == "neutral" for e in evidence)


def test_v8_nested_zero_range_directory_hash_and_external_url(prepared, tmp_path):
    source, run = prepared
    raw = (source / "covered.js").read_bytes()
    start = raw.index(b"  return")
    end = raw.index(b"\n", start) + 1
    folder = tmp_path / "v8"
    folder.mkdir()
    reports = [
        {"result": [{"url": (source / "covered.js").as_uri(), "functions": [
            {"ranges": [{"startOffset": 0, "endOffset": len(raw), "count": 1},
                        {"startOffset": start, "endOffset": end, "count": 0}]}]},
            {"url": (tmp_path / "outside.js").as_uri(), "functions": [
                {"ranges": [{"startOffset": 0, "endOffset": 11, "count": 1}]}]}]},
        {"result": [{"url": (source / "missed.js").as_uri(), "functions": [
            {"ranges": [{"startOffset": 0, "endOffset": (source / "missed.js").stat().st_size,
                         "count": 1}]}]}]},
    ]
    for i, report in enumerate(reports):
        (folder / f"coverage-{i}.json").write_text(json.dumps(report), encoding="utf-8")
    data = coverage.build_receipt(run, folder, source, "synthetic tests")
    assert [o["observed"] for o in data["observations"]] == [False, True]
    expected = hashlib.sha256()
    for p in sorted(folder.glob("coverage-*.json")):
        name, content = p.name.encode(), p.read_bytes()
        expected.update(len(name).to_bytes(8, "big") + name + len(content).to_bytes(8, "big") + content)
    assert data["raw_file"]["sha256"] == expected.hexdigest()
    assert len(observations.evidence_from_receipt(data, run)) == 2


def test_source_mismatch_or_no_covered_findings(prepared, tmp_path):
    source, run = prepared
    (source / "covered.js").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        coverage.build_receipt(run, FIXTURE / "coverage-final.json", source, "tests")
    shutil.copyfile(FIXTURE / "covered.js", source / "covered.js")
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"../outside.js": {"statementMap": {}, "s": {}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="no SAST finding lines"):
        coverage.build_receipt(run, empty, source, "tests")


def test_v8_offsets_count_characters_not_bytes(prepared, tmp_path):
    source, run = prepared
    text = "export function missed() {\n  return 'éééééééééé';\n}\nnext();\n"
    (source / "missed.js").write_text(text, encoding="utf-8", newline="\n")
    (run / "summary.json").write_text(json.dumps({"profile": "synthetic-profile",
                                                  "source_content_sha256": pin(source).content_sha256}))
    start = text.index("next();")
    folder = tmp_path / "v8"
    folder.mkdir()
    (folder / "coverage-0.json").write_text(json.dumps({"result": [{"url": (source / "missed.js").as_uri(),
        "functions": [{"ranges": [{"startOffset": 0, "endOffset": len(text), "count": 1},
                                  {"startOffset": 0, "endOffset": start, "count": 0}]}]}]}))
    (obs,) = coverage.build_receipt(run, folder, source, "tests")["observations"]
    assert obs["subject"]["line"] == 2 and obs["observed"] is False  # byte offsets would reach line 4


def _import(run, receipt, cov, source, out):
    return coverage.main(["import", str(run), str(receipt), "--coverage", str(cov), "--source", str(source),
                          "--out", str(out)])


def test_import_verifies_against_coverage(prepared, tmp_path):
    source, run = prepared
    rows = [_row(fid, "sast", "assess") | {"path": path, "line": 2}
            for fid, path in (("synthetic-covered", "covered.js"), ("synthetic-missed", "missed.js"))]
    (run / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (run / "evidence.jsonl").write_text("")
    cov, receipt = FIXTURE / "coverage-final.json", tmp_path / "receipt.json"
    coverage.main(["receipt", str(run), "--coverage", str(cov), "--source", str(source),
                   "--exercise", "npm test", "--out", str(receipt)])
    data = json.loads(receipt.read_text(encoding="utf-8"))
    data["observations"][1]["observed"] = True
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))
    with pytest.raises(ValueError, match="does not match its raw coverage"):
        _import(run, tampered, cov, source, tmp_path / "bad")
    assert _import(run, receipt, cov, source, tmp_path / "derived")["records"] == 2
