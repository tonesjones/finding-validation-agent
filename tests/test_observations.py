import hashlib
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from fva import observations
from fva.invariants import CONFIRMING_TYPES, RULE_TYPES, InvariantError, check_verdict
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)
SRC = "a" * 64


def obs_ev(eid, stance=Stance.neutral, kind="line_executed"):
    return EvidenceRecord(evidence_id=eid, finding_ids=("f1",), evidence_type=EvidenceType.runtime_observation,
                          method="observation:c8@1", stance=stance, summary="s", collected_at=NOW,
                          deployment_profile_id="p", tool_versions={"kind": kind})


def ev(eid, stance, et):
    return EvidenceRecord(evidence_id=eid, finding_ids=("f1",), evidence_type=et, method="m",
                          stance=stance, summary="s", collected_at=NOW, deployment_profile_id="p")


def vd(verdict, codes, eids):
    return Verdict(verdict_id="v", finding_id="f1", deployment_profile_id="p", verdict=verdict,
                   reason_codes=codes, confidence="high", evidence_ids=eids, narrative="n",
                   decided_at=NOW, decided_by={"method": "rules"})


def test_observation_is_neither_confirming_nor_rule_evidence():
    assert EvidenceType.runtime_observation not in CONFIRMING_TYPES
    assert EvidenceType.runtime_observation not in RULE_TYPES


@pytest.mark.parametrize("kind", ["loaded_package", "line_executed", "route_registered", "config_state"])
def test_observation_cannot_support(kind):
    with pytest.raises(ValidationError, match="cannot be supports"):
        obs_ev("o", Stance.supports, kind)


@pytest.mark.parametrize("kind", ["line_executed", "route_registered", "config_state"])
def test_only_unloaded_package_can_refute(kind):
    with pytest.raises(ValidationError, match="cannot be refutes"):
        obs_ev("o", Stance.refutes, kind)
    obs_ev("o", Stance.refutes, "loaded_package")


def test_observation_needs_profile_and_kind():
    with pytest.raises(ValidationError, match="deployment_profile_id"):
        EvidenceRecord.model_validate(obs_ev("o").model_dump() | {"deployment_profile_id": None})
    with pytest.raises(ValidationError, match="known kind"):
        EvidenceRecord.model_validate(obs_ev("o").model_dump() | {"tool_versions": {}})


def test_passive_only_verdict_cannot_be_confirmed():
    # Even a forged supporting observation (built without validation) cannot confirm.
    forged = EvidenceRecord.model_construct(**(obs_ev("o").model_dump() | {"stance": Stance.supports}))
    for code in ("RUNTIME_CONFIRMED", "RUNTIME_EXPLOITED", "REVIEWER_CONFIRMED"):
        with pytest.raises(InvariantError, match="confirmed requires"):
            check_verdict(vd(VerdictValue.confirmed, (code,), ("o",)), {"o": forged})


def test_passive_only_verdict_cannot_be_likely():
    with pytest.raises(InvariantError):
        check_verdict(vd(VerdictValue.likely, ("EXECUTED_UNDER_TEST",), ("o",)), {"o": obs_ev("o")})


def test_executed_under_test_needs_a_cited_argument():
    e = {"o": obs_ev("o"), "s": ev("s", Stance.neutral, EvidenceType.static_source)}
    with pytest.raises(InvariantError, match="supports"):
        check_verdict(vd(VerdictValue.likely, ("EXECUTED_UNDER_TEST",), ("o", "s")), e)
    e["m"] = ev("m", Stance.supports, EvidenceType.model_assessment)
    check_verdict(vd(VerdictValue.likely, ("EXECUTED_UNDER_TEST",), ("o", "s", "m")), e)


def test_unloaded_package_against_static_import_is_conflict():
    e = {"o": obs_ev("o", Stance.refutes, "loaded_package"),
         "d": ev("d", Stance.supports, EvidenceType.dependency_resolution)}
    with pytest.raises(InvariantError, match="CONFLICTING_EVIDENCE"):
        check_verdict(vd(VerdictValue.not_applicable, ("PACKAGE_NOT_LOADED",), ("o", "d")), e)
    check_verdict(vd(VerdictValue.not_applicable, ("PACKAGE_NOT_LOADED",), ("o",)), e)


# ------------------------------------------------------------------- receipts


@pytest.fixture
def run(tmp_path):
    rows = [{"finding_id": "sca1", "finding_type": "sca"}, {"finding_id": "sast1", "finding_type": "sast"}]
    (tmp_path / "findings.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (tmp_path / "summary.json").write_text(json.dumps({"profile": "p", "source_content_sha256": SRC}),
                                           encoding="utf-8")
    return tmp_path


def receipt(run, *obs):
    return {"format": "fva.runtime_observation/1", "profile_id": "p", "source_content_sha256": SRC,
            "findings_sha256": hashlib.sha256((run / "findings.jsonl").read_bytes()).hexdigest(),
            "collector": {"name": "c8-import", "version": "1"}, "exercise": "npm test",
            "raw_file": {"name": "coverage-final.json", "sha256": "b" * 64},
            "collected_at": "2026-10-04T12:00:00+00:00", "observations": list(obs)}


LOADED = {"kind": "loaded_package", "finding_ids": ["sca1"], "observed": False,
          "subject": {"name": "left-pad", "version": "1.0.0"}}
EXECUTED = {"kind": "line_executed", "finding_ids": ["sast1"], "observed": True,
            "subject": {"path": "routes/search.ts", "line": 23}}


def test_receipt_to_evidence(run):
    data = receipt(run, LOADED, EXECUTED)
    recs = observations.evidence_from_receipt(data, run)
    assert [r.stance for r in recs] == [Stance.refutes, Stance.neutral]
    h = observations.digest(data)
    assert recs[1].evidence_id == f"observation:{h}:1"
    assert recs[1].detail_ref == f"raw:sha256:{h}#/observations/1"
    assert recs[1].tool_versions == {
        "kind": "line_executed", "observed": "true", "collector": "c8-import@1", "exercise": "npm test",
        "receipt_sha256": h, "raw_sha256": "b" * 64, "source_content_sha256": SRC}
    assert recs[0].summary == "package left-pad@1.0.0 not observed under 'npm test'"


def test_not_executed_line_stays_neutral(run):
    rec, = observations.evidence_from_receipt(receipt(run, EXECUTED | {"observed": False}), run)
    assert rec.stance is Stance.neutral


def test_config_value_not_in_summary(run):
    cfg = {"kind": "config_state", "finding_ids": ["sast1"], "observed": True,
           "subject": {"key": "session.secret", "value": "hunter2"}}
    rec, = observations.evidence_from_receipt(receipt(run, cfg), run)
    assert "hunter2" not in rec.summary


@pytest.mark.parametrize("change, match", [
    ({"profile_id": "other"}, "does not match"),
    ({"source_content_sha256": "c" * 64}, "does not match"),
    ({"findings_sha256": "d" * 64}, "does not match"),
    ({"collected_at": "2026-10-04T12:00:00"}, "timezone"),
    ({"format": "fva.runtime_observation/2"}, "format"),
])
def test_receipt_binding_rejected(run, change, match):
    with pytest.raises((ValueError, ValidationError), match=match):
        observations.evidence_from_receipt(receipt(run, EXECUTED) | change, run)


@pytest.mark.parametrize("obs, match", [
    (LOADED | {"finding_ids": ["sast1"]}, "cannot describe a sast"),
    (EXECUTED | {"finding_ids": ["sca1"]}, "cannot describe a sca"),
    (EXECUTED | {"finding_ids": ["nope"]}, "unknown finding"),
    (EXECUTED | {"subject": {"path": "a.ts"}}, "subject needs keys"),
])
def test_bad_observation_rejected(run, obs, match):
    with pytest.raises((ValueError, ValidationError), match=match):
        observations.evidence_from_receipt(receipt(run, obs), run)
