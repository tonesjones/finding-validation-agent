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


def _mcp_run(tmp_path, names):
    import shutil
    from pathlib import Path
    fx = Path(__file__).parent / "fixtures"
    inp = tmp_path / "in"
    inp.mkdir()
    for n in names:
        shutil.copy(fx / f"polaris_mcp_{n}.json", inp / f"polaris_mcp_{n}.json")
    src = tmp_path / "src"
    (src / "routes").mkdir(parents=True)
    (src / "server.ts").write_text("import * as login from './routes/login'\n"
                                   "app.post('/rest/user/login', login.login())\n")
    (src / "routes/login.ts").write_text("x\n" * 40)
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    out = tmp_path / "out"
    s = pipeline.run(findings_spec=str(inp / "*.json"), source_root=src, profile=prof, client=ScriptedClient([]),
                     out_dir=out, dry_run=True, log=lambda *_: None)
    rows = [json.loads(l) for l in (out / "findings.jsonl").read_text().splitlines()]
    return s, rows


def test_sast_sca_only_scan_is_static_only(tmp_path):
    """Non-web apps have no DAST: no runtime mode, every finding still indexed and grouped."""
    s, rows = _mcp_run(tmp_path, ["sast", "sca"])
    assert s["scanner_mix"] == ["sast", "sca"] and s["runtime_mode"] == "none"
    assert len(rows) == 2 and all(r["issue_id"] for r in rows)
    assert s["grouped_issues"] == 2


def test_dast_findings_are_grouped_not_assessed(tmp_path):
    s, rows = _mcp_run(tmp_path, ["sast", "sca", "dast"])
    assert s["scanner_mix"] == ["dast", "sast", "sca"] and s["runtime_mode"] == "dast-evidence"
    (d,) = [r for r in rows if r["finding_type"] == "dast"]
    assert d["disposition"] == "runtime_only" and d["endpoint"] == "GET /rest/products/search"
    assert s["clusters"] <= 2  # DAST never becomes a model cluster
