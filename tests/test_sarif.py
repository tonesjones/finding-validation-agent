from pathlib import Path

from fva.adapters import sarif
from fva.schemas import FindingType, Severity

FIX = Path(__file__).parent / "fixtures" / "sample.sarif.json"


def _parse():
    return sarif.parse(FIX)


def test_ids_preserved_exactly():
    _, fs = _parse()
    assert [f.source_finding_id for f in fs] == ["0F3A-Case-Sensitive-ID", "a/v1=fp-0001", "0:2"]
    assert [f.source_finding_id_synthesized for f in fs] == [False, False, True]
    assert len({f.finding_id for f in fs}) == 3


def test_sast_mapping():
    run, fs = _parse()
    f = fs[0]
    assert f.finding_type is FindingType.sast
    assert f.rule_id == "js/sql-injection" and f.cwe == ("CWE-89",)
    assert f.severity is Severity.high  # security-severity 8.8 beats level
    assert f.location.path == "routes/login.ts" and (f.location.start_line, f.location.end_line) == (34, 36)
    assert f.location.function == "login"
    assert f.source_tool == "sarif:ExampleScanner"
    assert f.scanner_metadata["source_commit"] == "abc123"
    assert f.raw_evidence_ref == f"raw:sha256:{run.raw_artifact_sha256}#/runs/0/results/0"


def test_sca_mapping():
    _, fs = _parse()
    f = fs[1]
    assert f.finding_type is FindingType.sca
    assert (f.package.name, f.package.version, f.package.ecosystem) == ("jsonwebtoken", "0.4.0", "npm")
    assert f.package.advisory_id == "CVE-2015-9235" and f.cwe == ("CWE-347",)


def test_default_level_and_path_normalization():
    _, fs = _parse()
    f = fs[2]
    assert f.severity is Severity.low  # rule defaultConfiguration.level = note
    assert f.location.path == "test/api/userApiSpec.ts"


def test_rejects_other_versions(tmp_path):
    p = tmp_path / "x.sarif"
    p.write_text('{"version": "2.0.0", "runs": []}')
    import pytest
    with pytest.raises(ValueError):
        sarif.parse(p)
