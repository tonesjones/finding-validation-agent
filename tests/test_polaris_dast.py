import hashlib
import copy
import json
from pathlib import Path

import pytest

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


OBSERVED = FIX.parent / "polaris_dast_observed.json"


def test_observed_post_and_get_endpoints():
    _, (post, get) = polaris.load_dast(OBSERVED)
    assert (post.endpoint.method, post.endpoint.path) == ("POST", "/api/action")
    assert (get.endpoint.method, get.endpoint.path) == ("GET", "/api/status")
    assert post.source_finding_id == "DAST-SAMPLE-POST-001"
    assert (post.cwe, post.severity, post.title) == (("CWE-755",), Severity.medium, "Server Error")
    assert get.title == "Deprecated TLS Protocol Version"
    assert post.endpoint.parameter is None
    assert post.endpoint.parameter_location is None


def test_structured_evidence_retains_provenance_without_signed_urls():
    _, (post, _) = polaris.load_dast(OBSERVED)
    record, = post.scanner_metadata["dast_evidence"]
    assert [a["relation"] for a in record["artifacts"]] == ["request", "response", "screenshot"]
    assert record["artifacts"][0]["raw_ref"] == (
        f"raw:sha256:{hashlib.sha256(OBSERVED.read_bytes()).hexdigest()}#/issues/0/occurrenceProperties/7/value/0/_links/0"
    )
    assert record["target_ref"].endswith("/attack/target")
    assert post.scanner_metadata["attack_target_ref"].endswith("/occurrenceProperties/6/value")
    assert (record["scope"], record["segment"]) == ("Endpoint", "StatusCode")
    dumped = post.model_dump_json()
    for private in ("demo.invalid", "artifacts.invalid", "FAKE-SIGNED-TOKEN",
                    "FAKE-PRIVATE-TARGET", "SYNTHETIC-TENANT"):
        assert private not in dumped
    assert "request_snippet" not in post.scanner_metadata
    assert "response_snippet" not in post.scanner_metadata


@pytest.mark.parametrize("missing", ["method", "location"])
def test_missing_endpoint_fact_never_becomes_root_or_get(missing):
    issue = copy.deepcopy(json.loads(OBSERVED.read_text())["_items"][0])
    issue["occurrenceProperties"] = [p for p in issue["occurrenceProperties"] if p["key"] != missing]
    finding = polaris.from_issue(issue, run_id="sample", raw_digest="0" * 64, pointer="/issues/0")
    assert finding.endpoint is None
    assert finding.scanner_metadata["endpoint_missing_fields"] == [missing]
    from fva.correlation.runtime_link import link
    from fva.schemas import Finding, FindingLocation
    static = Finding(finding_id="static", run_id="sample", source_tool="sample",
                     source_finding_id="static", rule_id="sample", cwe=("CWE-755",),
                     title="sample", severity=Severity.medium, finding_type=FindingType.sast,
                     location=FindingLocation(path="action.js", start_line=1),
                     raw_evidence_ref="raw:sha256:0#/issues/0")
    assert link(static, finding, {("ALL", "/api/action"): {"action.js"}}) is None


def test_dast_type_sidecar_uses_issue_id_and_ignores_ambiguous_weakness_id():
    issue = copy.deepcopy(json.loads(OBSERVED.read_text())["_items"][1])
    correct = issue.pop("type")
    wrong = json.loads(OBSERVED.read_text())["_items"][0]["type"]
    finding = polaris.from_issue(issue, run_id="sample", raw_digest="0" * 64, pointer="/issues/0",
                                 types={issue["weaknessId"]: wrong})
    assert finding.title == "Untitled issue"
    assert finding.scanner_metadata["type_details_missing"] is True
    finding = polaris.from_issue(issue, run_id="sample", raw_digest="0" * 64, pointer="/issues/0",
                                 types={issue["id"]: correct, issue["weaknessId"]: wrong})
    assert finding.title == "Deprecated TLS Protocol Version"
    assert "type_details_missing" not in finding.scanner_metadata


def test_dast_inline_type_wins_over_sidecar():
    issue = json.loads(OBSERVED.read_text())["_items"][1]
    wrong = json.loads(OBSERVED.read_text())["_items"][0]["type"]
    finding = polaris.from_issue(issue, run_id="sample", raw_digest="0" * 64, pointer="/issues/0",
                                 types={issue["id"]: wrong})
    assert finding.title == "Deprecated TLS Protocol Version"


REAL_LIST = FIX.parent / "polaris_dast_real_list.json"
REAL_TYPES = FIX.parent / "polaris_dast_real_types.json"


def test_real_fva_envelope_loads_all_ids_and_missing_methods(tmp_path):
    page = tmp_path / "page-0001.json"
    page.write_bytes(REAL_LIST.read_bytes())
    (tmp_path / "dast-types.json").write_bytes(REAL_TYPES.read_bytes())
    _, findings = polaris.load_dast(page)
    assert [f.source_finding_id for f in findings] == [f"DAST-REAL-{i:02d}" for i in range(1, 12)]
    assert sum(f.endpoint is not None for f in findings) == 9
    missing = [f for f in findings if f.endpoint is None]
    assert len(missing) == 2
    assert all(f.scanner_metadata["endpoint_missing_fields"] == ["method"] for f in missing)
    assert all(f.endpoint is None or f.endpoint.parameter is None for f in findings)
    assert all("type_details_missing" not in f.scanner_metadata for f in findings)
    assert findings[0].title == "Server Error"
    assert findings[-1].title == "Crawl Report"
    for f in findings:
        assert f.scanner_metadata["dast_evidence"]
        assert all(a["raw_ref"].startswith("raw:sha256:")
                   for e in f.scanner_metadata["dast_evidence"] for a in e["artifacts"])


def test_interpolated_dast_type_text_redacts_target_and_credentials():
    issue = polaris._unwrap(json.loads(REAL_LIST.read_text()))[-1]
    for p in issue["occurrenceProperties"]:
        if p["key"] == "location":
            p["value"] = "http://fixture.local:3000/"
    issue["type"] = {"altName": "Crawl Report", "_localized": {
        "name": "Crawl Report for fixture.local:3000",
        "otherDetails": [{"key": "description", "value":
            "Scanned http://fixture.local:3000/\nCookie: session=FAKE-REPORT-SECRET\n" + "x" * 600}]}}
    finding = polaris.from_dast_issue(issue, run_id="sample", raw_digest="0" * 64, pointer="/issues/0")
    text = finding.model_dump_json()
    assert "fixture.local" not in text and ":3000" not in text
    assert "FAKE-REPORT-SECRET" not in text
    assert "[REDACTED]" in finding.description
    assert len(finding.description) > 500  # Only HTTP snippets are truncated.
    assert finding.endpoint is None
