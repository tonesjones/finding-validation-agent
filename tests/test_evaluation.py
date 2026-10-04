import json

import pytest

from fva.__main__ import load_profile, main
from fva.evaluation import preflight, preflight_dir, pilot_status, main as eval_main
from fva.schemas import DeploymentProfile


@pytest.fixture
def app(tmp_path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "worker.js").write_text("import './routes.js'\n")
    (src / "routes.js").write_text("import * as search from './search.js'\napp.get('/search', search.run)\n")
    (src / "search.js").write_text("export const run = () => 'ok'\n")
    (src / "package.json").write_text('{"dependencies":{"demo":"1.0.0"}}')
    profile = DeploymentProfile(profile_id="demo", name="demo", language_packs=("node",),
                                entrypoints=("worker.js", "routes.js"))
    expected = tmp_path / "routes.json"
    expected.write_text('[{"method":"GET","path":"/search","handlers":["search.js"]}]')
    return src, profile, expected


def test_external_profile_and_exclusion(app, tmp_path):
    src, profile, expected = app
    path = tmp_path / "profile.json"
    path.write_text(profile.model_dump_json())
    assert load_profile(profile_file=str(path)) == profile
    with pytest.raises(ValueError, match="mutually exclusive"):
        load_profile("juiceshop", str(path))
    with pytest.raises(SystemExit):
        main(["assess", "--source", str(src), "--profile", "juiceshop", "--profile-file", str(path)])
    path.write_text('{"profile_id":"x","name":"x","typo":true}')
    with pytest.raises(ValueError):
        load_profile(profile_file=str(path))


def test_pilot_status_is_bound_to_preparation_receipt_and_call_audits(tmp_path):
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "cases.jsonl").write_text('{"case_id":"a"}\n{"case_id":"b"}\n')
    from fva.evaluation import seal, write_json
    seal(prepared, "prepared.json", [prepared / "cases.jsonl"])
    manifest = json.loads((prepared / "prepared.json").read_text())
    receipt = tmp_path / "receipt.json"
    labels = {"reviewer": "reviewer", "prepared_sha256": manifest["sha256"],
              "gold_sha256": "0" * 64}
    write_json(receipt, labels)
    run = tmp_path / "run"
    run.mkdir()
    write_json(run / "run.json", {"prepared_sha256": manifest["sha256"], "labels_receipt": labels,
                                  "requested_model": "gpt-6-sol"})
    rows = []
    sealed_files = [run / "run.json"]
    for i, case_id in enumerate(("a", "b")):
        call_dir = run / f"case-{i:04d}"
        call_dir.mkdir()
        call = {"requested_model": "gpt-6-sol", "observed_model": "gpt-6-sol",
                "response_sha256": str(i), "audit": {"complete": True, "observed_model": "gpt-6-sol",
                "tool_items": [], "unknown_events": []}}
        write_json(call_dir / "call.json", call)
        sealed_files.append(call_dir / "call.json")
        rows.append({"case_id": case_id, "model": {"requested_model": "gpt-6-sol",
                     "observed_model": "gpt-6-sol", "response_sha256": str(i)},
                     "processing_failure": False})
    (run / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    sealed_files.append(run / "results.jsonl")
    seal(run, "outputs.json", sealed_files)
    result = pilot_status(prepared, run, receipt)
    assert result["matching_label_receipt"] is True
    assert result["prepared_cases"] == result["assessment_cases"] == 2
    assert result["model_verified"] and result["audit_clean"] and result["case_ids_match"]
    assert "private-hash" not in str(result) and "response_sha256" not in str(result)

    seal(prepared, "prepared.json", [])
    incomplete = json.loads((prepared / "prepared.json").read_text())
    incomplete_labels = {**labels, "prepared_sha256": incomplete["sha256"]}
    write_json(receipt, incomplete_labels)
    write_json(run / "run.json", {"prepared_sha256": incomplete["sha256"],
                                  "labels_receipt": incomplete_labels, "requested_model": "gpt-6-sol"})
    seal(run, "outputs.json", sealed_files)
    with pytest.raises(ValueError, match="status inputs are not sealed"):
        pilot_status(prepared, run, receipt)
    seal(prepared, "prepared.json", [prepared / "cases.jsonl"])
    write_json(receipt, labels)
    write_json(run / "run.json", {"prepared_sha256": manifest["sha256"],
                                  "labels_receipt": labels, "requested_model": "gpt-6-sol"})
    for omitted in (run / "run.json", run / "results.jsonl", run / "case-0001" / "call.json"):
        seal(run, "outputs.json", [p for p in sealed_files if p != omitted])
        with pytest.raises(ValueError, match="not sealed"):
            pilot_status(prepared, run, receipt)
    seal(run, "outputs.json", sealed_files)

    wrong_model_call = run / "case-0001" / "call.json"
    wrong_model = json.loads(wrong_model_call.read_text())
    wrong_model["observed_model"] = "gpt-6-luna"
    wrong_model["audit"]["observed_model"] = "gpt-6-luna"
    write_json(wrong_model_call, wrong_model)
    seal(run, "outputs.json", sealed_files)
    result = pilot_status(prepared, run, receipt)
    assert result["model_verified"] is False and result["audit_clean"] is False

    wrong_model_call.unlink()
    sealed_files.remove(wrong_model_call)
    rows[1] = {"case_id": "b", "processing_failure": "call failed before metadata was written"}
    (run / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    seal(run, "outputs.json", sealed_files)
    result = pilot_status(prepared, run, receipt)
    assert result["assessment_cases"] == 2 and result["processing_failures"] == 1
    assert result["case_ids_match"] is True
    assert result["model_verified"] is False and result["audit_clean"] is False

    wrong_run = run / "wrong"
    wrong_run.mkdir()
    write_json(wrong_run / "run.json", {"prepared_sha256": "wrong", "labels_receipt": labels})
    seal(wrong_run, "outputs.json", [wrong_run / "run.json"])
    with pytest.raises(ValueError, match="different frozen preparation"):
        pilot_status(prepared, wrong_run, receipt)


def test_preflight_without_findings(app, tmp_path):
    src, profile, expected = app
    out = tmp_path / "out"
    result = preflight(src, profile, out, expected_routes=expected)
    assert result["dast_ready"]
    assert result["routes"] == [{"method": "GET", "path": "/search", "handlers": ["search.js"]}]
    assert next(r for r in result["files"] if r["path"] == "search.js")["reachable"]
    assert result["dependencies"]["declared"][0]["name"] == "demo"
    assert json.loads((out / "preflight.json").read_text())["profile_sha256"]


def test_route_registration_must_be_entrypoint(app, tmp_path):
    src, profile, expected = app
    profile = profile.model_copy(update={"entrypoints": ("worker.js",)})
    result = preflight(src, profile, tmp_path / "out", expected_routes=expected)
    assert not result["dast_ready"] and "incorrect route mapping" in result["blocking_reasons"][0]
    result = preflight(src, profile, tmp_path / "out2")
    assert not result["dast_ready"]


def test_external_preflight_cli_only(app, tmp_path, monkeypatch, capsys):
    src, profile, expected = app
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(profile.model_dump_json())
    # Treat the test directory as an external handoff for the CLI boundary.
    external = tmp_path / "external" / "preflight"
    import fva.evaluation as evaluation
    def restricted(path):
        raise ValueError("case artifacts require ignored data/")
    monkeypatch.setattr(evaluation, "artifact_dir", restricted)
    args = ["prepare", "--source", str(src), "--profile-file", str(profile_path),
            "--expected-routes", str(expected), "--out", str(external)]
    eval_main(args)
    assert (external / "preflight.json").exists() and "DAST launch: ready" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        eval_main(args + ["--canonical", str(tmp_path / "must-not-read.jsonl")])


def test_preflight_output_path_safety(app, tmp_path):
    src, _, _ = app
    for path in (src, src / "reports", src.parent, tmp_path / "other" / ".git" / "reports"):
        with pytest.raises(ValueError):
            preflight_dir(path, src)
    frozen = tmp_path / "frozen"
    frozen.mkdir()
    (frozen / "prepared.json").write_text("{}")
    with pytest.raises(ValueError, match="frozen"):
        preflight_dir(frozen, src)


def test_git_inventory_failure_never_reads_untracked_files(tmp_path, monkeypatch):
    from fva.correlation import source_pin
    (tmp_path / ".git").mkdir()
    (tmp_path / "untracked.js").write_text("not part of pinned source")
    monkeypatch.setattr(source_pin, "_git", lambda *a: None)
    with pytest.raises(ValueError, match="refusing archive fallback"):
        list(source_pin.iter_files(tmp_path))
