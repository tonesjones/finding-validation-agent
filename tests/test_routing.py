import json

import pytest

from fva import pipeline
from fva.adapters import polaris
from fva.correlation.locate import SourceIndex
from fva.reasoning.model import ScriptedClient
from fva.reasoning.routing import ASTRA, JUNIOR, SENIOR, Router, escalation_reason, route
from fva.schemas import DeploymentProfile

SRC = {"server.ts": "import './routes/a'\n",
       "routes/a.ts": "const unused = 1\nconst q = `SELECT ${req.body.email}`\nsequelize.query(q)\n"}


def finding(tmp_path, cwe, severity="medium", fid="1", tool="SAST", line=1):
    rows = tmp_path / f"f{fid}.jsonl"
    rows.write_text(json.dumps({"candidate_id": fid, "tool": tool, "severity": severity, "issue_type": "x",
                                "cwe": cwe, "location": "routes/a.ts", "line": line}) + "\n")
    return polaris.load(rows)[1][0]


@pytest.fixture
def idx(tmp_path):
    src = tmp_path / "src"
    for rel, text in SRC.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    return SourceIndex.build(src)


def reply(stance="supports", conf="high", quote="const unused = 1", line=1):
    return json.dumps({"claims": [{"statement": "s", "stance": stance, "citations": [
        {"path": "routes/a.ts", "line": line, "quote": quote}]}], "confidence": conf})


@pytest.mark.parametrize("cwe,severity,tier", [
    ("CWE-563", "low", JUNIOR), ("CWE-798", "medium", JUNIOR), ("CWE-400", "medium", JUNIOR),
    ("CWE-89", "high", SENIOR), ("CWE-918", "medium", SENIOR), ("CWE-347", "low", SENIOR),
    ("CWE-345", "low", SENIOR), ("CWE-613", "low", SENIOR), ("CWE-676", "low", SENIOR),
    ("CWE-563", "critical", SENIOR), ("CWE-400", "high", SENIOR)])
def test_route_policy(tmp_path, cwe, severity, tier):
    assert route([finding(tmp_path, cwe, severity)])[0] == tier


def test_senior_member_pulls_cluster_to_senior(tmp_path):
    group = [finding(tmp_path, "CWE-563", "low", "1"), finding(tmp_path, "CWE-563", "critical", "2")]
    assert route(group) == (SENIOR, "critical severity")


def test_astra_only_when_flagged(tmp_path):
    f = finding(tmp_path, "CWE-89", "high", fid="hard-1")
    assert route([f])[0] == SENIOR and route([f], frozenset({"hard-1"}))[0] == ASTRA


def routed(tmp_path, idx, cwe, severity, junior_replies, senior_replies=(), **kw):
    j, s = ScriptedClient(list(junior_replies), "luna"), ScriptedClient(list(senior_replies), "sol")
    r = Router({JUNIOR: j, SENIOR: s}).assess([finding(tmp_path, cwe, severity)], idx,
                                              source_content_sha256="0" * 64, profile_id="p", **kw)
    return r, j, s


def test_clean_junior_answer_is_kept(tmp_path, idx):
    r, j, s = routed(tmp_path, idx, "CWE-563", "low", [reply("non_security")])
    assert r.tier == JUNIOR and len(j.prompts) == 1 and not s.prompts
    tv = r.result.evidence.tool_versions
    assert tv["routing_tier"] == JUNIOR and tv["agent_model"] == "luna" and "CWE-563" in tv["routing_reason"]


@pytest.mark.parametrize("junior,severity,why", [
    (reply(quote="invented line"), "low", "citations rejected"),
    ("not json", "low", "unparseable output"),
    (reply(conf="low"), "low", "low confidence"),
    (reply("refutes"), "high", "refutes high/critical"),
    (json.dumps({"claims": [json.loads(reply("supports"))["claims"][0], json.loads(reply("refutes"))["claims"][0]],
                 "confidence": "high"}), "low", "conflicting claims")])
def test_escalates_once_to_senior(tmp_path, idx, junior, severity, why):
    # CWE-563 at high severity still routes junior (bounded CWE beats the high-severity default)
    r, j, s = routed(tmp_path, idx, "CWE-563", severity, [junior], [reply(quote="invented", conf="low")])
    assert r.tier == SENIOR and len(j.prompts) == 1 and len(s.prompts) == 1  # senior not retried even if weak
    assert r.attempts[0]["escalate"] == why and r.reason == f"escalated from junior: {why}"
    assert r.result.evidence.tool_versions["routing_tier"] == SENIOR


def test_low_confidence_credential_is_not_escalated(tmp_path, idx):
    r, _, s = routed(tmp_path, idx, "CWE-798", "medium", [reply(conf="low")])
    assert r.tier == JUNIOR and not s.prompts


def test_credential_still_escalates_on_rejected_citation(tmp_path, idx):
    r, _, s = routed(tmp_path, idx, "CWE-798", "medium", [reply(quote="invented", conf="low")], [reply()])
    assert r.tier == SENIOR and r.attempts[0]["escalate"] == "citations rejected"


def test_junior_refuting_low_finding_is_not_escalated(tmp_path, idx):
    r, _, s = routed(tmp_path, idx, "CWE-563", "low", [reply("refutes")])
    assert r.tier == JUNIOR and not s.prompts


def test_senior_first_never_escalates(tmp_path, idx):
    r, j, s = routed(tmp_path, idx, "CWE-89", "high", [], ["garbage"])
    assert r.tier == SENIOR and not j.prompts and len(r.attempts) == 1


def test_reported_model_survives_cache(tmp_path, idx):
    class Reporting(ScriptedClient):
        def complete(self, system, user, **kw):
            self.last_reported_model, self.last_tokens = "gpt-6-luna", 12345
            return super().complete(system, user, **kw)
    j = Reporting([reply("non_security")], "codex-cli:gpt-6-luna")
    router, f = Router({JUNIOR: j, SENIOR: ScriptedClient([])}), finding(tmp_path, "CWE-563", "low")
    kw = dict(source_content_sha256="0" * 64, profile_id="p", cache_dir=tmp_path / "cache")
    first, second = router.assess([f], idx, **kw), router.assess([f], idx, **kw)
    assert second.result.cached and second.result.agent_model == first.result.agent_model == "gpt-6-luna"
    assert second.result.evidence.tool_versions["requested_model"] == "codex-cli:gpt-6-luna"
    assert second.result.tokens == first.result.tokens == 12345 and second.attempts[0]["tokens"] == 12345


def test_escalation_reason_none_for_good_answer(tmp_path, idx):
    r, _, _ = routed(tmp_path, idx, "CWE-563", "low", [reply("non_security")])
    assert escalation_reason(r.result, [finding(tmp_path, "CWE-563", "low")]) is None


def test_pipeline_reports_tiers_and_escalations(tmp_path):
    src = tmp_path / "src"
    for rel, text in SRC.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    rows = [{"candidate_id": "A", "tool": "SAST", "severity": "low", "issue_type": "Unused", "cwe": "CWE-563",
             "location": "routes/a.ts", "line": 1},
            {"candidate_id": "B", "tool": "SAST", "severity": "high", "issue_type": "SQLi", "cwe": "CWE-89",
             "location": "routes/a.ts", "line": 2}]
    fj = tmp_path / "f.jsonl"
    fj.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    router = Router({JUNIOR: ScriptedClient([reply(conf="low")], "luna"),
                     SENIOR: ScriptedClient([reply("non_security"), reply(quote="req.body.email", line=2)], "sol")})
    out = tmp_path / "out"
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=router, out_dir=out,
                     log=lambda *_: None)
    assert s["model"] == "routed" and s["escalations"] == {"low confidence": 1}
    assert s["tiers"][JUNIOR]["calls"] == 1 and s["tiers"][SENIOR]["calls"] == 2
    a = {r["source_finding_ids"][0]: r for r in map(json.loads, (out / "assessments.jsonl").read_text().splitlines())}
    assert a["A"]["tier"] == SENIOR and [x["tier"] for x in a["A"]["attempts"]] == [JUNIOR, SENIOR]
    assert a["B"]["tier"] == SENIOR and a["B"]["routing_reason"].startswith("security-sensitive")

    d = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=Router({}), out_dir=tmp_path / "dry",
                     dry_run=True, log=lambda *_: None)
    assert d["first_pass_tiers"] == {JUNIOR: 1, SENIOR: 1}
