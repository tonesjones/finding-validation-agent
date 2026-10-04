import json

import pytest

from fva.adapters import polaris
from fva.correlation.locate import SourceIndex
from fva.reasoning.assessor import assess
from fva.reasoning.model import ScriptedClient
from fva.schemas import EvidenceType, Stance


@pytest.fixture
def env(tmp_path):
    src = tmp_path / "src"
    (src / "routes").mkdir(parents=True)
    (src / "routes" / "login.ts").write_text(
        "import { models } from '../models'\n"
        "export function login(req) {\n"
        "  const q = `SELECT * FROM Users WHERE email = '${req.body.email}'`\n"
        "  const apiKey = 'sk_live_abcdefghijkl'\n"
        "  return models.sequelize.query(q)\n"
        "}\n")
    rows = tmp_path / "f.jsonl"
    rows.write_text(json.dumps({"candidate_id": "1", "tool": "SAST", "severity": "high", "issue_type": "SQL Injection",
                                "cwe": "CWE-89", "checker": "SQLI", "location": "routes/login.ts", "line": 3}) + "\n")
    f = polaris.load(rows)[1][0]
    return f, SourceIndex.build(src), tmp_path


def run(env, reply, **kw):
    f, idx, tmp = env
    client = ScriptedClient([json.dumps(reply) if isinstance(reply, dict) else reply])
    res = assess(f, idx, client, source_content_sha256="0" * 64, profile_id="p", **kw)
    return res, client


def claim(stance, line, quote, code=None, path="routes/login.ts"):
    return {"statement": "s", "stance": stance, "suggested_reason_code": code,
            "citations": [{"path": path, "line": line, "quote": quote}]}


def test_verified_claim_accepted(env):
    res, _ = run(env, {"claims": [claim("supports", 3, "WHERE email = '${req.body.email}'", "RUNTIME_CONFIRMED")],
                       "confidence": "high"})
    assert res.evidence.evidence_type is EvidenceType.model_assessment
    assert res.evidence.stance is Stance.supports and len(res.accepted) == 1 and not res.rejected
    assert res.accepted[0]["suggested_reason_code"] is None or res.accepted[0]["suggested_reason_code"] == "RUNTIME_CONFIRMED"


@pytest.mark.parametrize("bad", [
    claim("refutes", 99, "whatever"),  # line beyond EOF
    claim("refutes", 3, "parameterized query"),  # quote not on that line
    claim("refutes", 1, "import", path="routes/invented.ts"),  # invented file
])
def test_hallucinated_citations_rejected(env, bad):
    res, _ = run(env, {"claims": [bad], "confidence": "high"})
    assert res.rejected and not res.accepted and res.evidence.stance is Stance.neutral


def test_reason_code_must_match_stance(env):
    res, _ = run(env, {"claims": [claim("supports", 5, "sequelize.query(q)", "TEST_ONLY")]})
    assert res.accepted[0]["suggested_reason_code"] is None


def test_conflicting_claims_are_neutral(env):
    res, _ = run(env, {"claims": [claim("supports", 3, "SELECT * FROM Users"), claim("refutes", 5, "sequelize.query")]})
    assert res.evidence.stance is Stance.neutral


def test_uncited_claim_kept_as_neutral(env):
    res, _ = run(env, {"claims": [{"statement": "probably fine", "stance": "refutes", "citations": []}]})
    assert res.accepted[0]["stance"] == "neutral" and res.evidence.stance is Stance.neutral


def test_garbage_response(env):
    res, _ = run(env, "I think it's vulnerable!")
    assert res.evidence.stance is Stance.neutral and res.rejected


def test_prompt_is_redacted(env):
    _, client = run(env, {"claims": []})
    _, user = client.prompts[0]
    assert "sk_live_abcdefghijkl" not in user and "[REDACTED]" in user
    assert "routes/login.ts" in user and "SELECT * FROM Users" in user


def test_cache(env, tmp_path):
    reply = {"claims": [claim("supports", 3, "SELECT * FROM Users")]}
    first, _ = run(env, reply, cache_dir=tmp_path / "cache")
    f, idx, _ = env
    second = assess(f, idx, ScriptedClient([]), source_content_sha256="0" * 64, profile_id="p", cache_dir=tmp_path / "cache")
    assert second.cached and second.evidence.stance is first.evidence.stance


def _claim(stance, path, line, code=None):
    return {"stance": stance, "suggested_reason_code": code, "statement": "s",
            "citations": [{"path": path, "line": line, "quote": "q"}]}


def test_cited_precondition_refutation_outranks_restated_sink():
    from fva.reasoning.assessor import _aggregate
    sink = ("routes/a.ts", 40)
    restated = _claim("supports", "routes/a.ts", 41)
    precondition = _claim("refutes", "routes/a.ts", 12, "NO_ATTACKER_CONTROL")
    assert _aggregate([restated, precondition], sink) is Stance.refutes
    # a supports claim that cites the input path keeps the conflict neutral
    assert _aggregate([restated, _claim("supports", "routes/b.ts", 5), precondition], sink) is Stance.neutral
    # a refutation without a precondition code, or citing only the sink, does not win
    assert _aggregate([restated, _claim("refutes", "routes/a.ts", 12)], sink) is Stance.neutral
    assert _aggregate([restated, _claim("refutes", "routes/a.ts", 40, "NO_ATTACKER_CONTROL")], sink) is Stance.neutral
    assert _aggregate([restated, precondition]) is Stance.neutral  # no sink location (e.g. SCA)


def test_prompt_lists_only_model_reason_codes():
    from fva.reasoning.assessor import MODEL_CODES, SYSTEM
    assert "MODEL_ONLY_REFUTATION" not in MODEL_CODES and "REVIEWER_CONFIRMED" not in MODEL_CODES
    assert {"NO_ATTACKER_CONTROL", "VULNERABLE_FUNCTION_NOT_CALLED", "INSUFFICIENT_EVIDENCE"} <= set(MODEL_CODES)
    assert "Restating what the scanner flagged" in SYSTEM
