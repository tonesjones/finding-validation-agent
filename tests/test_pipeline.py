import json

from fva import pipeline
from fva.reasoning.model import ScriptedClient
from fva.schemas import DeploymentProfile


def test_pipeline_end_to_end(tmp_path):
    src = tmp_path / "src"
    for rel, text in {"server.ts": "import './routes/login'\n",
                      "routes/login.ts": "const q = `SELECT ${req.body.email}`\nsequelize.query(q)\n",
                      "test/a.test.ts": "const password = 'x'\n"}.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    rows = [{"candidate_id": "A", "tool": "SAST", "severity": "high", "issue_type": "SQLi", "cwe": "CWE-89",
             "location": "routes/login.ts", "line": 1},
            {"candidate_id": "B", "tool": "SAST", "severity": "high", "issue_type": "SQLi", "cwe": "CWE-89",
             "location": "routes/login.ts", "line": 1},  # same sink -> same cluster
            {"candidate_id": "C", "tool": "SAST", "severity": "low", "issue_type": "Cred", "cwe": "CWE-798",
             "location": "test/a.test.ts", "line": 1}]  # outside deployment -> skipped
    fj = tmp_path / "f.jsonl"
    fj.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    reply = json.dumps({"claims": [{"statement": "user input in query", "stance": "supports",
                                    "citations": [{"path": "routes/login.ts", "line": 1, "quote": "req.body.email"}]}]})
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    out = tmp_path / "out"
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=ScriptedClient([reply]),
                     out_dir=out, cache_dir=tmp_path / "cache", log=lambda *_: None)
    assert s["clusters"] == 1 and s["skipped"] == {"surface:test": 1} and s["stance"] == {"supports": 1}
    a = [json.loads(l) for l in (out / "assessments.jsonl").read_text().splitlines()]
    assert a[0]["source_finding_ids"] == ["A", "B"]
    ev = [json.loads(l) for l in (out / "evidence.jsonl").read_text().splitlines()]
    model_ev = [e for e in ev if e["evidence_type"] == "model_assessment"]
    assert len(model_ev) == 1 and len(model_ev[0]["finding_ids"]) == 2
