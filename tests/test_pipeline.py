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
    # the rule-skipped test-file finding keeps the boundary record its closure cites
    (b,) = [e for e in ev if e["evidence_type"] == "deployment_boundary"]
    assert b["stance"] == "refutes" and b["method"] == "path_rule:test" and b["detail_ref"]
    from fva.export import worksheet
    rows = {r["source_finding_id"]: r for r in worksheet.build(out)}
    assert rows["C"]["fva_verdict"] == "not_applicable" and rows["C"]["evidence_ids"] == b["evidence_id"]


def test_version_drift_does_not_close_and_keeps_neutral_evidence(tmp_path):
    from pathlib import Path
    from fva.export import worksheet
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.ts").write_text("import multer from 'multer'\n")
    rows = [{"candidate_id": "S", "tool": "SCA", "severity": "medium", "issue_type": "DoS", "component": "multer",
             "component_version": "1.4.5-lts.1"}]  # the lockfile has another multer version
    fj = tmp_path / "f.jsonl"
    fj.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    out = tmp_path / "out"
    reply = json.dumps({"claims": [], "confidence": "low"})
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=ScriptedClient([reply]),
                     out_dir=out, lockfile=Path(__file__).parent / "fixtures" / "package-lock.min.json",
                     log=lambda *_: None)
    assert s["skipped"] == {} and s["clusters"] == 1
    ev = [json.loads(l) for l in (out / "evidence.jsonl").read_text().splitlines()]
    (d,) = [e for e in ev if e["evidence_type"] == "dependency_resolution"]
    assert d["stance"] == "neutral" and d["method"] == "inventory:version_drift"
    (r,) = worksheet.build(out)
    assert r["fva_verdict"] != "not_applicable" and "VERSION_DRIFT" not in r["reason_codes"]


def _lodash_run(tmp_path, installed, advisory):
    """Scanner saw lodash 4.17.19 (raw MCP shape); the lockfile installs `installed`; template() is called."""
    import copy
    from pathlib import Path
    raw = json.loads((Path(__file__).parent / "fixtures" / "polaris_mcp_sca.json").read_text())
    data = json.loads(raw["content"][0]["text"])
    props = {"component-name": "lodash", "component-version-name": "4.17.19", "vulnerability-id": advisory,
             "component-origin-external-id": "lodash/4.17.19", "location": "lodash 4.17.19"}
    data["data"]["occurrenceProperties"] = [
        {"key": p["key"], "value": props.get(p["key"], p["value"])} for p in data["data"]["occurrenceProperties"]]
    raw = copy.deepcopy(raw)
    raw["content"][0]["text"] = json.dumps(data)
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "polaris_mcp_sca.json").write_text(json.dumps(raw))
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.js").write_text("const _ = require('lodash')\n_.template(userInput)\n")
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": installed}}, "node_modules/lodash": {"version": installed}}}))
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.js",))
    out = tmp_path / "out"
    reply = json.dumps({"claims": [], "confidence": "low"})
    s = pipeline.run(findings_spec=str(inp / "*.json"), source_root=src, profile=prof,
                     client=ScriptedClient([reply]), out_dir=out, lockfile=lock, log=lambda *_: None)
    return s, out


def test_drift_between_affected_versions_stays_open_through_exports(tmp_path):
    from fva.export import report, sarif_export, triage_report, worksheet
    s, out = _lodash_run(tmp_path, "4.17.20", "CVE-2021-23337")  # 4.17.19 and 4.17.20 are both affected
    assert s["skipped"] == {} and s["clusters"] == 1
    ev = [json.loads(l) for l in (out / "evidence.jsonl").read_text().splitlines()]
    assert {"inventory:version_drift", "advisory_range:affected"} <= {e["method"] for e in ev}
    (row,) = worksheet.build(out)
    assert row["fva_verdict"] != "not_applicable"
    triage_report.write(out)
    (t,) = [json.loads(l) for l in (out / "triage.jsonl").read_text().splitlines()]
    assert t["verdict"] != "not_applicable"  # open: likely (template is called) or needs_review
    report.write(out)
    tickets = [json.loads(l) for l in (out / "tickets.jsonl").read_text().splitlines()]
    assert tickets and "EEEE5555FFFF6666AAAA7777BBBB8888" in json.dumps(tickets)
    sarif_export.write(out)
    results = json.loads((out / "sca.sarif").read_text())["runs"][0]["results"]
    assert [r["guid"] for r in results] == ["EEEE5555FFFF6666AAAA7777BBBB8888"]


def test_drift_to_unaffected_installed_version_closes_by_advisory_range(tmp_path):
    from fva.export import worksheet
    s, out = _lodash_run(tmp_path, "4.17.21", "CVE-2021-23337")  # fixed in 4.17.21
    assert s["skipped"] == {"dependency:advisory_version_unaffected": 1} and s["clusters"] == 0
    (row,) = worksheet.build(out)
    assert row["fva_verdict"] == "not_applicable" and row["reason_codes"] == "ADVISORY_VERSION_MISMATCH"


def test_drift_with_unknown_advisory_stays_open(tmp_path):
    from fva.export import worksheet
    s, out = _lodash_run(tmp_path, "4.17.20", "CVE-2099-0001")
    assert s["skipped"] == {} and s["clusters"] == 1
    (row,) = worksheet.build(out)
    assert row["fva_verdict"] != "not_applicable"


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
    # rule evidence for skipped findings never enters a prompt (prompt hashes, and so the model cache, are unchanged)
    assert not any("deployment_boundary" in p.read_text() for p in (out / "prompts").glob("*.txt"))
    return s, rows


def test_sast_sca_only_scan_is_static_only(tmp_path):
    """Non-web apps have no DAST: no runtime mode, every finding still indexed and grouped."""
    s, rows = _mcp_run(tmp_path, ["sast", "sca"])
    assert s["scanner_mix"] == ["sast", "sca"] and s["runtime_mode"] == "none"
    assert s["scanner_counts"] == {"sast": 1, "sca": 1}
    assert len(rows) == 2 and all(r["issue_id"] for r in rows)
    assert s["grouped_issues"] == 2


def test_dast_findings_are_grouped_not_assessed(tmp_path):
    s, rows = _mcp_run(tmp_path, ["sast", "sca", "dast"])
    assert s["scanner_mix"] == ["dast", "sast", "sca"] and s["runtime_mode"] == "dast-evidence"
    assert s["scanner_counts"] == {"dast": 1, "sast": 1, "sca": 1}
    (d,) = [r for r in rows if r["finding_type"] == "dast"]
    assert d["disposition"] == "runtime_only" and d["endpoint"] == "GET /rest/products/search"
    assert s["clusters"] <= 2  # DAST never becomes a model cluster


def test_credential_clusters_can_skip_the_model(tmp_path):
    src = tmp_path / "src"
    (src / "routes").mkdir(parents=True)
    (src / "server.ts").write_text("import './routes/login'\n")
    (src / "routes/login.ts").write_text("const password = 'x'\nsequelize.query(q)\n")
    rows = [{"candidate_id": "K", "tool": "SAST", "severity": "high", "issue_type": "Cred", "cwe": "CWE-798",
             "location": "routes/login.ts", "line": 1},
            {"candidate_id": "Q", "tool": "SAST", "severity": "high", "issue_type": "SQLi", "cwe": "CWE-89",
             "location": "routes/login.ts", "line": 2}]
    fj = tmp_path / "f.jsonl"
    fj.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    reply = json.dumps({"claims": [], "confidence": "low"})
    client = ScriptedClient([reply])  # exactly one model call: the SQLi cluster
    out = tmp_path / "out"
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=client, out_dir=out,
                     credential_model="skip", log=lambda *_: None)
    assert s["clusters"] == 1 and s["skipped"] == {"model:credential_runtime_only": 1} and len(client.prompts) == 1
    disp = {json.loads(l)["source_finding_id"]: json.loads(l)["disposition"]
            for l in (out / "findings.jsonl").read_text().splitlines()}
    assert disp == {"K": "model:credential_runtime_only", "Q": "assess"}
    from fva.export import worksheet
    k = next(r for r in worksheet.build(out) if r["source_finding_id"] == "K")
    assert k["fva_verdict"] == "needs_review" and k["evidence_ids"]  # rule evidence still recorded


def test_summary_records_versions(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.ts").write_text("console.log(1)\n")
    fj = tmp_path / "f.jsonl"
    fj.write_text("")
    prof = DeploymentProfile(profile_id="p", name="t", language_packs=("node",), entrypoints=("server.ts",))
    s = pipeline.run(findings_spec=str(fj), source_root=src, profile=prof, client=ScriptedClient([]),
                     out_dir=tmp_path / "out", cache_dir=tmp_path / "cache", log=lambda *_: None)
    v = json.loads((tmp_path / "out" / "summary.json").read_text())["versions"]
    assert v == s["versions"]
    assert v["python"] and v["reason_codes"] and v["source_commit"] is None and v["cli"] == {}
    assert not any(str(tmp_path) in str(x) for x in v.values())


def test_cli_versions_never_fail_the_run():
    import sys
    from pathlib import Path

    from fva.reasoning.routing import Router

    class Cli:
        def __init__(self, exe):
            self._argv = [exe, "-"]

    snap = type("Snap", (), {"vcs_commit": None, "vcs_dirty": None})()
    v = pipeline.versions(Router({"a": Cli(sys.executable), "b": Cli("no-such-cli-xyz")}), snap)
    assert v["cli"]["no-such-cli-xyz"] is None
    assert v["cli"][Path(sys.executable).stem].startswith("Python 3")
