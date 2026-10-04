"""L3 verdict rules for passive runtime observations, and receipt re-verification at verdict time."""
import json
from datetime import datetime, timezone

import pytest

from fva import observations
from fva.export.worksheet import build
from fva.invariants import InvariantError, check_verdict
from fva.runtime import digest, read_rows
from fva.schemas import EvidenceRecord, EvidenceType, Stance, Verdict, VerdictValue as V
from fva.verdicts import suggest_verdict
from tests.test_worksheet import _row

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)
SRC = "a" * 64


def obs(eid, kind, observed, exercise="npm test"):
    return EvidenceRecord(
        evidence_id=eid, finding_ids=("f",), evidence_type=EvidenceType.runtime_observation,
        method="observation:c@1", stance=Stance.refutes if kind == "loaded_package" and not observed else Stance.neutral,
        summary="s", collected_at=NOW, deployment_profile_id="p",
        tool_versions={"kind": kind, "observed": str(observed).lower(), "exercise": exercise})


def ev(eid, et, stance=Stance.neutral, method="m"):
    return EvidenceRecord(evidence_id=eid, finding_ids=("f",), evidence_type=et, method=method, stance=stance,
                          summary="s", collected_at=NOW, deployment_profile_id="p")


def reach(status):
    return ev(f"r-{status}", EvidenceType.reachability,
              Stance.refutes if status == "imported_only_outside_deployment" else Stance.neutral,
              f"static_import_graph:{status}")


DEP = ev("dep", EvidenceType.dependency_resolution)
LOC = ev("loc", EvidenceType.static_source)
MODEL_SUPPORTS = ev("ms", EvidenceType.model_assessment, Stance.supports)
MODEL_REFUTES = ev("mr", EvidenceType.model_assessment, Stance.refutes)


def suggest(ftype, evs, disp="assess", verified=None):
    row = {"finding_id": "f", "finding_type": ftype, "disposition": disp, "deployment_profile_id": "p"}
    ids = frozenset(e.evidence_id for e in evs if e.evidence_type is EvidenceType.runtime_observation)
    verdict, codes, _, cited = suggest_verdict(row, evs, verified_observation_ids=ids if verified is None else verified)
    return verdict, codes, {e.evidence_id for e in cited}


# ------------------------------------------------------------------- SCA


def test_loaded_vulnerable_package_is_likely():
    verdict, codes, cited = suggest("sca", [DEP, reach("imported_by_reachable_code"), MODEL_SUPPORTS,
                                            obs("o", "loaded_package", True)])
    assert (verdict, codes) == (V.likely, ("VULNERABLE_VERSION_IMPORTED",)) and "o" in cited


def test_loaded_package_alone_is_not_likely():
    verdict, codes, _ = suggest("sca", [DEP, reach("imported_by_reachable_code"), obs("o", "loaded_package", True)])
    assert (verdict, codes) == (V.needs_review, ("INSUFFICIENT_EVIDENCE",))


@pytest.mark.parametrize("status, disp", [
    ("not_imported_directly", "assess"),
    ("declared_not_imported", "assess"),
    ("imported_only_outside_deployment", "reachability:outside_deployment"),
])
def test_not_loaded_and_not_shipped_is_not_applicable(status, disp):
    verdict, codes, cited = suggest("sca", [DEP, reach(status), obs("o", "loaded_package", False)], disp)
    assert (verdict, codes) == (V.not_applicable, ("PACKAGE_NOT_LOADED",)) and "o" in cited


@pytest.mark.parametrize("status", ["imported_by_reachable_code", "imported_by_shipped_code"])
def test_not_loaded_but_shipped_import_never_closes(status):
    verdict, codes, _ = suggest("sca", [DEP, reach(status), obs("o", "loaded_package", False)])
    assert (verdict, codes) == (V.needs_review, ("INSUFFICIENT_EVIDENCE",))


@pytest.mark.parametrize("exercise", ["startup only", "Startup  Only", "npm start"])
def test_not_loaded_at_startup_only_does_not_close(exercise):
    verdict, _, _ = suggest("sca", [DEP, reach("not_imported_directly"), obs("o", "loaded_package", False, exercise)])
    assert verdict is V.needs_review


def test_not_loaded_without_reachability_does_not_close():
    assert suggest("sca", [DEP, obs("o", "loaded_package", False)])[0] is V.needs_review


def test_not_loaded_in_one_receipt_and_loaded_in_another_does_not_close():
    evs = [DEP, reach("not_imported_directly"), obs("o1", "loaded_package", False),
           obs("o2", "loaded_package", True, "startup only")]
    assert suggest("sca", evs)[0] is V.needs_review


def test_not_loaded_against_model_support_is_conflict():
    verdict, codes, _ = suggest("sca", [DEP, reach("not_imported_directly"), MODEL_SUPPORTS,
                                        obs("o", "loaded_package", False)])
    assert (verdict, codes) == (V.needs_review, ("CONFLICTING_EVIDENCE",))


def test_unverified_observation_is_ignored():
    verdict, _, cited = suggest("sca", [DEP, reach("not_imported_directly"), obs("o", "loaded_package", False)],
                                verified=frozenset())
    assert verdict is V.needs_review and "o" not in cited


# ------------------------------------------------------------------- SAST


def test_executed_line_with_cited_support_is_likely():
    verdict, codes, cited = suggest("sast", [LOC, reach("in_entrypoint_graph"), MODEL_SUPPORTS,
                                             obs("o", "line_executed", True)])
    assert (verdict, codes) == (V.likely, ("EXECUTED_UNDER_TEST",)) and "o" in cited


def test_executed_line_alone_is_not_likely():
    verdict, _, _ = suggest("sast", [LOC, reach("in_entrypoint_graph"), obs("o", "line_executed", True)])
    assert verdict is V.needs_review


@pytest.mark.parametrize("others", [
    [LOC, MODEL_SUPPORTS],
    [LOC, MODEL_REFUTES],
    [LOC, ev("mn", EvidenceType.model_assessment, Stance.non_security)],
    [LOC],
])
def test_not_executed_changes_nothing(others):
    without = suggest("sast", others)
    verdict, codes, _ = suggest("sast", [*others, obs("o", "line_executed", False)])
    assert (verdict, codes) == without[:2]


def test_not_executed_never_closes():
    verdict, _, _ = suggest("sast", [LOC, reach("not_in_entrypoint_graph"), MODEL_REFUTES,
                                     obs("o", "line_executed", False)])
    assert verdict is V.needs_review


# ------------------------------------------------------------------- invariants


def vd(verdict, code, evs):
    return Verdict(verdict_id="v", finding_id="f", deployment_profile_id="p", verdict=verdict, reason_codes=(code,),
                   confidence="medium", evidence_ids=tuple(e.evidence_id for e in evs), narrative="n",
                   decided_at=NOW, decided_by={"method": "rules"})


@pytest.mark.parametrize("evs, match", [
    ([DEP, reach("not_imported_directly")], "not-loaded observation"),
    ([DEP, reach("not_imported_directly"), obs("o", "loaded_package", False, "startup only")], "more than startup"),
    ([DEP, obs("o", "loaded_package", False)], "no shipped import"),
    ([DEP, reach("imported_by_shipped_code"), obs("o", "loaded_package", False)], "no shipped import"),
    ([DEP, reach("not_imported_directly"), obs("o", "loaded_package", False), obs("o2", "loaded_package", True)],
     "package loaded"),
])
def test_package_not_loaded_invariant(evs, match):
    with pytest.raises(InvariantError, match=match):
        check_verdict(vd(V.not_applicable, "PACKAGE_NOT_LOADED", evs), {e.evidence_id: e for e in evs})


@pytest.mark.parametrize("evs, match", [
    ([LOC, MODEL_SUPPORTS, obs("o", "line_executed", False)], "line executed"),
    ([LOC, obs("o", "line_executed", True), ev("h", EvidenceType.human_review, Stance.supports)], "static or model"),
])
def test_executed_under_test_invariant(evs, match):
    with pytest.raises(InvariantError, match=match):
        check_verdict(vd(V.likely, "EXECUTED_UNDER_TEST", evs), {e.evidence_id: e for e in evs})


# ------------------------------------------------------------------- receipts at verdict time


@pytest.fixture
def imported(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "findings.jsonl").write_text(json.dumps(_row("f", "sca", "assess") | {"package": "left-pad@1.0.0"}) + "\n")
    (run / "summary.json").write_text(json.dumps({"profile": "p", "source_content_sha256": SRC}))
    reachability = ev("r", EvidenceType.reachability, method="static_import_graph:not_imported_directly")
    (run / "evidence.jsonl").write_text(reachability.model_dump_json() + "\n")
    receipt = {"format": observations.FORMAT, "profile_id": "p", "source_content_sha256": SRC,
               "findings_sha256": observations.file_digest(run / "findings.jsonl"),
               "collector": {"name": "c", "version": "1"}, "exercise": "npm test",
               "raw_file": {"name": "raw", "sha256": "b" * 64}, "collected_at": "2026-10-04T12:00:00+00:00",
               "observations": [{"kind": "loaded_package", "finding_ids": ["f"], "observed": False,
                                 "subject": {"name": "left-pad", "version": "1.0.0"}}]}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    out = tmp_path / "derived"
    observations.import_receipt(run, path, out, lambda r: None)
    return out, out / "observations" / f"{digest(receipt)}.json"


def test_imported_receipt_closes_after_reverification(imported):
    out, _ = imported
    warnings = []
    row, = build(out, warnings=warnings)
    assert (row["fva_verdict"], row["reason_codes"]) == ("not_applicable", "PACKAGE_NOT_LOADED") and not warnings


@pytest.mark.parametrize("tamper", ["receipt", "evidence", "missing"])
def test_tampered_observation_is_ignored(imported, tamper):
    out, receipt_path = imported
    if tamper == "receipt":
        receipt_path.write_text(receipt_path.read_text().replace("npm test", "npm run test:api"))
    elif tamper == "missing":
        receipt_path.unlink()
    else:
        rows = read_rows(out / "evidence.jsonl")
        rows[-1]["tool_versions"]["exercise"] = "npm run test:api"
        (out / "evidence.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    warnings = []
    row, = build(out, warnings=warnings)
    assert row["fva_verdict"] == "needs_review" and "runtime_observation" not in row["evidence_summary"]
    assert warnings == ["1 runtime observation record(s) do not match a stored receipt and are ignored."]
