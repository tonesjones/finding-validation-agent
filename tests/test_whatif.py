import json

from fva.__main__ import main
from fva.export import whatif
from fva.export.whatif import AUTO_CLOSE, FIX, REVIEW, project
from tests.test_score import _key
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q)


def _row(verdict="needs_review", scanner="sast", evidence="model_assessment:neutral"):
    return {"fva_verdict": verdict, "scanner": scanner, "evidence_summary": evidence}


def _key_row(code):
    return {"code": code, "verdict": "", "classification": ""}


def test_decided_rows_keep_their_bucket():
    for verdict, bucket in (("not_applicable", AUTO_CLOSE), ("valid_non_security", AUTO_CLOSE),
                            ("likely", FIX), ("confirmed", FIX)):
        p = project(_row(verdict), _key_row("MITIGATED_IN_CONTEXT"))
        assert p["now"] == p["optimistic"] == p["conservative"] == bucket and not p["signal"]


def test_closing_signals():
    p = project(_row(scanner="sca"), _key_row("VERSION_DRIFT"))
    assert (p["signal"], p["optimistic"], p["conservative"]) == ("loaded_package_version", AUTO_CLOSE, AUTO_CLOSE)
    p = project(_row(), _key_row("TEST_ONLY"))
    assert p["signal"] == "deployed_inventory" and p["conservative"] == AUTO_CLOSE
    p = project(_row(scanner="sca"), _key_row("ADVISORY_PRECONDITION_ABSENT"))
    assert p["optimistic"] == AUTO_CLOSE and p["conservative"] == REVIEW
    assert p["why_review"] == whatif.CONSERVATIVE_PRECONDITION


def test_positive_signals_need_a_cited_argument_for_sast_when_conservative():
    p = project(_row(evidence="reachability:neutral | model_assessment:supports"), _key_row("RUNTIME_CONFIRMED"))
    assert (p["signal"], p["optimistic"], p["conservative"]) == ("line_coverage", FIX, FIX)
    p = project(_row(), _key_row("BROWSER_EXECUTION_CONFIRMED"))
    assert p["optimistic"] == FIX and p["conservative"] == REVIEW and p["why_review"] == whatif.NO_SUPPORT
    p = project(_row(scanner="sca"), _key_row("REACHABLE_NOT_EXPLOITED"))
    assert (p["signal"], p["conservative"]) == ("loaded_package_and_function_calls", FIX)


def test_undecidable_and_unknown_stay_with_a_person():
    for code in ("MITIGATED_IN_CONTEXT", "ACTIVE_CREDENTIAL", "QUALITY_NOT_SECURITY"):
        p = project(_row(), _key_row(code))
        assert p["optimistic"] == p["conservative"] == REVIEW and p["why_review"] == whatif.UNDECIDABLE[code]
    assert project(_row(), None)["why_review"] == "finding newer than the answer key"
    assert project(_row(), _key_row(""))["why_review"] == "no passive signal mapped to this key label"


def test_whatif_run(run, tmp_path):
    key = _key(tmp_path, [("POL-t", "test_only"), ("POL-l", "true_positive_runtime_validated"),
                          ("POL-m", "true_positive_runtime_validated"), ("POL-d", "true_positive_runtime_validated"),
                          ("POL-q", "valid_quality_finding_not_security")])
    s = whatif.whatif(run, key)
    assert s["now"] == {AUTO_CLOSE: 2, FIX: 2, REVIEW: 1}
    assert s["conservative"] == s["optimistic"] == {AUTO_CLOSE: 2, FIX: 3, REVIEW: 0}  # POL-m: cited supports
    m = json.loads((run / "whatif.json").read_text())
    assert m["signals"] == {"line_coverage": 1} and m["incorrect_demotions_now"] == 0
    assert "Ceiling estimate" in (run / "whatif.md").read_text()
    assert (run / "whatif_rows.csv").read_text(encoding="utf-8-sig").startswith("source_finding_id")


def test_whatif_cli(run, tmp_path, capsys):
    key = _key(tmp_path, [("POL-m", "mitigated_or_context_not_vulnerable")])
    main(["whatif", str(run), "--key", str(key)])
    assert "'review': 1" in capsys.readouterr().out
    reasons = json.loads((run / "whatif.json").read_text())["review_reasons_conservative"]
    assert reasons == {whatif.UNDECIDABLE["MITIGATED_IN_CONTEXT"]: 1}
