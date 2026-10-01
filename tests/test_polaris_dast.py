import hashlib
from pathlib import Path

from fva.adapters import polaris
from fva.schemas import FindingType, Severity

FIX = Path(__file__).parent / "fixtures" / "polaris_mcp_dast.json"


def _load():
    return polaris.load_dast(FIX)


def test_endpoint_fields():
    _, (f,) = _load()
    assert f.finding_type is FindingType.dast and f.severity is Severity.high
    assert f.cwe == ("CWE-89",) and f.title == "SQL Injection" and f.rule_id == "dast.sqli"
    e = f.endpoint
    assert (e.method, e.path, e.parameter, e.parameter_location) == ("GET", "/rest/products/search", "q", "query")
    assert f.raw_evidence_ref.endswith("#/issues/0")


def test_load_mcp_equivalent():
    r1, f1 = polaris.load_mcp(FIX)
    r2, f2 = _load()
    assert r1.raw_artifact_sha256 == r2.raw_artifact_sha256 and [x.finding_id for x in f1] == [x.finding_id for x in f2]


def test_no_host_anywhere():
    _, (f,) = _load()
    dumped = f.model_dump_json()
    assert "juice.internal" not in dumped and ":3000" not in dumped
    assert "q=test" not in f.endpoint.model_dump_json()


def test_secrets_redacted_and_truncated():
    _, (f,) = _load()
    m = f.scanner_metadata
    dumped = f.model_dump_json()
    assert "FAKE-TOKEN" not in dumped and "FAKE-COOKIE" not in dumped
    assert "[REDACTED]" in m["request_snippet"]
    assert all(len(m[k]) <= 500 for k in ("request_snippet", "response_snippet"))


def test_internal_context_stripped():
    _, (f,) = _load()
    dumped = f.model_dump_json()
    assert "_links" not in dumped and "tenantId" not in dumped and "FAKE-TENANT" not in dumped
    assert f.scanner_metadata["context"]["toolType"] == "dast"


def test_raw_fixture_unchanged():
    before = hashlib.sha256(FIX.read_bytes()).hexdigest()
    _load()
    assert hashlib.sha256(FIX.read_bytes()).hexdigest() == before
