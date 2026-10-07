from datetime import datetime, timezone

import pytest

from fva.missing import EXCEPTION_GAPS, SAST_CWE_GAPS, missing_evidence
from fva.schemas import EvidenceRecord


def ev(kind, stance="neutral"):
    return EvidenceRecord(evidence_id=kind + stance, finding_ids=("f",), evidence_type=kind,
                          stance=stance, method="m", summary="SECRET-PAYLOAD https://private.invalid",
                          detail_ref="SECRET-RECEIPT", collected_at=datetime.now(timezone.utc),
                          deployment_profile_id="p")


@pytest.mark.parametrize("code,text", EXCEPTION_GAPS.items())
@pytest.mark.parametrize("field", ["reason", "exception"])
def test_exception_gaps(code, text, field):
    result = missing_evidence("needs_review", [code] if field == "reason" else [],
                              [code] if field == "exception" else [], {}, [])
    assert result == text[0].upper() + text[1:] + "."


@pytest.mark.parametrize("disposition,expected", [
    ("dependency:unresolved_name", "package-name resolution"),
    ("dependency:version_drift", "scanner versus installed version"),
    ("dependency:not_installed", "package installation"),
    ("dependency:scanned_version_present", "installed version"),
    ("dependency:advisory_version_unaffected", "advisory version applicability"),
    ("dependency:vulnerable_function_not_called", "vulnerable-function call-site"),
    ("dependency:advisory_precondition_absent", "advisory precondition"),
    ("dependency:unknown_check", "dependency check"),
])
def test_dependency(disposition, expected):
    result = missing_evidence("needs_review", ["INSUFFICIENT_EVIDENCE"], [],
                              {"disposition": disposition, "package": "@example/pkg@1.0"}, [])
    assert expected in result and "@example/pkg" in result and "inconclusive" in result
    assert ("call-site scan" if "called" in disposition or "precondition" in disposition
            else "lockfile resolution") in result


@pytest.mark.parametrize("surface", ["test", "fixture", "infrastructure", "api_spec", "documentation", "unknown"])
def test_surface(surface):
    result = missing_evidence("needs_review", [], [], {"disposition": "surface:" + surface}, [])
    assert surface.replace("_", " ") + " surface ships" in result


def test_reachability():
    result = missing_evidence("needs_review", [], [], {"disposition": "reachability:outside_deployment"}, [])
    assert "static import-path evidence from a deployed entrypoint" in result.lower()
    assert "establish or rule out reachability" in result


def test_likely_and_confirmed():
    assert "static and model evidence cannot confirm" in missing_evidence("likely", [], [], {}, [])
    assert missing_evidence("confirmed", [], [], {}, [ev("dast_observation", "supports")]).startswith(
        "No evidence is missing for confirmation;")


@pytest.mark.parametrize("cited,finding,expected", [
    ([], {}, "Cited evidence supporting a decision is missing."),
    ([ev("static_source")], {}, "Evidence sufficient to decide whether this issue applies is missing."),
    ([ev("static_source")], {"finding_type": "sast"}, "Source or reachability evidence"),
    ([ev("dependency_resolution")], {"finding_type": "sca", "package": "example@1"}, "deployed use of example"),
    ([ev("dast_observation")], {"finding_type": "dast"}, "Supporting DAST evidence linked"),
    ([ev("runtime_probe")], {}, "Verified runtime evidence with a linked negative control"),
    ([ev("advisory_precondition")], {}, "rule-derived advisory-precondition evidence"),
    ([ev("model_assessment", "supports")], {}, "Rule-derived source, dependency or reachability evidence"),
    ([ev("model_assessment", "refutes")], {}, "The model argues for closure"),
    ([ev("static_source", "supports"), ev("static_source", "refutes")], {}, "supporting and refuting observations"),
])
def test_evidence_and_fallback(cited, finding, expected):
    result = missing_evidence("needs_review", ["INSUFFICIENT_EVIDENCE"], [], finding, cited)
    assert expected in result
    assert "SECRET" not in result and "https://" not in result


@pytest.mark.parametrize("cwe,text", SAST_CWE_GAPS.items())
def test_sast_cwe_gap(cwe, text):
    result = missing_evidence("needs_review", [], [], {"finding_type": "sast", "cwe": [cwe]}, [ev("static_source")])
    assert result == text[0].upper() + text[1:] + "."


def test_sast_cwe_uses_first_mapped_in_list_order():
    result = missing_evidence("needs_review", [], [],
                              {"finding_type": "sast", "cwe": ["CWE-999", "CWE-89", "CWE-79"]}, [ev("static_source")])
    assert "query without parameterization" in result
    assert "output sink" not in result


@pytest.mark.parametrize("finding", [{"cwe": ["CWE-999"]}, {"cwe": None}, {"cwe": []}, {}])
def test_sast_unmapped_or_missing_cwe_uses_generic(finding):
    result = missing_evidence("needs_review", [], [], {"finding_type": "sast", **finding}, [ev("static_source")])
    assert result == "Source or reachability evidence deciding whether the reported security condition applies is missing."


@pytest.mark.parametrize("cwe", ["CWE-79<script>", "https://private.invalid/CWE-79"])
def test_sast_malicious_cwe_is_not_echoed(cwe):
    result = missing_evidence("needs_review", [], [], {"finding_type": "sast", "cwe": [cwe]}, [ev("static_source")])
    assert result == "Source or reachability evidence deciding whether the reported security condition applies is missing."
    assert cwe not in result


@pytest.mark.parametrize("package", ["https://private.invalid/SECRET", "ghp_abcdefghijklmno", "bearer SECRET", "pkg|SECRET"])
def test_untrusted_metadata_is_not_echoed(package):
    result = missing_evidence("needs_review", [], [],
                              {"disposition": "dependency:https://private.invalid/SECRET", "package": package}, [])
    assert "SECRET" not in result and "https://" not in result and package not in result


def test_multiple_gaps_are_one_sentence():
    result = missing_evidence("likely", [], ["PROFILE_MISMATCH", "LOW_CONFIDENCE"],
                              {"disposition": "surface:test"}, [])
    assert result.count(".") == 1
    assert "deployment profile" in result and "confidence" in result and "surface ships" in result
