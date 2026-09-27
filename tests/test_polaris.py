from pathlib import Path

from fva.adapters import mapping, polaris
from fva.schemas import FindingType, Severity

FIX = Path(__file__).parent / "fixtures"


def test_polaris_sast_and_sca():
    run, (a, b) = polaris.load(FIX / "polaris_sample.jsonl", source_commit="abc")
    assert run.source_tool == "polaris" and run.source_commit == "abc"
    assert a.source_finding_id == "AAAA0000BBBB1111CCCC2222DDDD3333"
    assert a.finding_type is FindingType.sast and a.rule_id == "SIGMA.sql_injection"
    assert a.location.path == "routes/login.ts" and a.location.start_line == 34
    assert a.location.function is None  # "unknown" treated as missing
    assert a.scanner_metadata["scanner_link"].startswith("https://")
    assert b.source_finding_id == "eeee4444ffff5555"  # case preserved
    assert b.finding_type is FindingType.sca and b.location is None
    assert b.severity is Severity.critical and b.rule_id == "CVE-2015-9235"
    assert (b.package.name, b.package.version, b.package.linked_advisory_ids) == (
        "Auth0_node-jsonwebtoken", "0.4.0", ("BDSA-2015-0001",))
    assert b.scanner_metadata["reachability"] == "REACHABLE"
    assert b.raw_evidence_ref.endswith("#L2")


def test_ids_are_stable_across_reimports():
    _, f1 = polaris.load(FIX / "polaris_sample.jsonl")
    _, f2 = polaris.load(FIX / "polaris_sample.jsonl")
    assert [f.finding_id for f in f1] == [f.finding_id for f in f2]


def test_generic_csv_mapping():
    fm = mapping.FieldMap(source_tool="acme", id="Issue ID", rule_id="Rule", title="Name", severity="Sev",
                          finding_type="Kind", path="File", line="Line", cwe="CWE")
    _, (a, b) = mapping.load(FIX / "generic.csv", fm)
    assert a.source_finding_id == " id-with-space "  # byte-for-byte, whitespace kept
    assert a.severity is Severity.medium and a.cwe == ("CWE-327", "CWE-328")
    assert a.raw_evidence_ref.endswith("#L2")
    assert b.location.start_line is None and b.cwe == ()


def test_unmapped_severity_fails_loudly(tmp_path):
    import pytest
    p = tmp_path / "x.jsonl"
    p.write_text('{"candidate_id": "1", "tool": "SAST", "severity": "spicy", "issue_type": "t"}\n')
    with pytest.raises(ValueError, match="severity"):
        polaris.load(p)
