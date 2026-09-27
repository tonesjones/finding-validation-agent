from pathlib import Path

from fva.adapters import polaris
from fva.correlation.dependency import reconcile
from fva.langpacks import REGISTRY
from fva.schemas import FindingType, Severity

FIX = Path(__file__).parent / "fixtures"


def test_sast_issue():
    run, (f,) = polaris.load_mcp(FIX / "polaris_mcp_sast.json")
    assert f.source_finding_id == "AAAA1111BBBB2222CCCC3333DDDD4444"
    assert f.finding_type is FindingType.sast and f.severity is Severity.high
    assert f.rule_id == "sigma.sqli" and f.cwe == ("CWE-89",) and f.title == "SQL Injection"
    assert (f.location.path, f.location.start_line) == ("routes/login.ts", 34)
    assert f.scanner_metadata["checker"] == "SQLI" and f.scanner_metadata["language"] == "TypeScript"
    assert "remediation" not in f.scanner_metadata and f.description.startswith("The software constructs")
    assert f.raw_evidence_ref.endswith("#/issues/0")


def test_sca_issue_uses_polaris_package_identity():
    _, (f,) = polaris.load_mcp(FIX / "polaris_mcp_sca.json")
    assert f.finding_type is FindingType.sca and f.location is None
    assert (f.package.name, f.package.version, f.package.ecosystem) == ("multer", "1.4.5-lts.1", "npm")
    m = f.scanner_metadata
    assert m["reachability"] == "REACHABLE" and m["reachability_evidence_count"] == 4
    assert m["declared_at"] == ["package.json:135"] and m["context"]["toolType"] == "sca"
    assert "_links" not in str(m) and "tenantId" not in str(m)


def test_mcp_and_flat_ids_agree():
    """Same Polaris issue id -> same finding_id whichever adapter ingested it."""
    import json, tempfile
    _, (m,) = polaris.load_mcp(FIX / "polaris_mcp_sast.json")
    d = Path(tempfile.mkdtemp()) / "f.jsonl"
    d.write_text(json.dumps({"candidate_id": m.source_finding_id, "tool": "SAST", "severity": "high",
                             "issue_type": "SQL Injection"}) + "\n")
    _, (flat,) = polaris.load(d)
    assert flat.finding_id == m.finding_id


def test_reconciles_without_alias_table():
    inv = REGISTRY["node"].read_inventory(FIX / "package-lock.min.json")
    _, (f,) = polaris.load_mcp(FIX / "polaris_mcp_sca.json")
    assert reconcile(f, inv).status == "version_drift"  # fixture lock has multer 1.4.5-lts.2
