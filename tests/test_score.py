import json

from fva.export import score
from tests.test_worksheet import run  # noqa: F401  (fixture: findings t,l,m,d,q)


def _key(tmp_path, rows):
    p = tmp_path / "key.jsonl"
    p.write_text("\n".join(json.dumps({"candidate_id": c, "classification": k}) for c, k in rows) + "\n")
    return p


def test_outcome_rules():
    assert score.outcome("confirmed", "confirmed") == "agree"
    assert score.outcome("confirmed", "likely") == "agree_static"
    assert score.outcome("confirmed", "needs_review") == "unresolved"
    assert score.outcome("confirmed", "not_applicable") == "incorrect_demotion"
    assert score.outcome("needs_review", "valid_non_security") == "incorrect_demotion"
    assert score.outcome("not_applicable", "likely") == "over_flag"
    assert score.outcome("not_applicable", "valid_non_security") == "wrong_clearance_kind"
    assert score.outcome(None, "likely") == "not_in_key"


def test_score_run(run, tmp_path):
    key = _key(tmp_path, [("POL-t", "test_only"), ("POL-l", "true_positive_runtime_validated"),
                          ("POL-m", "true_positive_runtime_validated"), ("POL-d", "true_positive_runtime_validated"),
                          ])  # POL-q missing from the key
    s = score.score(run, key)
    assert s["rows"] == 5 and s["scored"] == 4
    assert s["outcomes"] == {"agree": 2, "agree_static": 1, "unresolved": 1, "not_in_key": 1}
    assert s["incorrect_demotions"] == 0 and s["agreement"] == 0.75
    m = json.loads((run / "score.json").read_text())
    assert m["reason_code_match_on_agree"] == 1  # TEST_ONLY matches; DAST_OBSERVED != RUNTIME_CONFIRMED
    assert m["by"]["tier"]["rules"]["agree"] == 2
    assert "Incorrect demotions (0)" in (run / "score.md").read_text()
    assert (run / "score_rows.csv").read_text(encoding="utf-8-sig").startswith("source_finding_id")
