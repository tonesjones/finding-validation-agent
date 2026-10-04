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


def test_pilot_status_is_aggregate_and_checks_receipt_binding(tmp_path):
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "cases.jsonl").write_text('{"case_id":"a"}\n{"case_id":"b"}\n')
    from fva.evaluation import seal, write_json
    seal(prepared, "prepared.json", [prepared / "cases.jsonl"])
    manifest = json.loads((prepared / "prepared.json").read_text())
    receipt = tmp_path / "receipt.json"
    write_json(receipt, {"reviewer": "reviewer", "prepared_sha256": manifest["sha256"],
                         "gold_sha256": "private-hash-not-returned"})
    audit = tmp_path / "audit.json"
    write_json(audit, {"cases": 2, "all_models_verified": "gpt-6-sol", "all_audits_clean": True,
                       "answer_key_case_ids_exact_match": True, "verdict_counts": {"private": "omitted"}})
    score = tmp_path / "score.json"
    write_json(score, {"responses": 2, "processing_failures": 0, "case_rows": "omitted"})
    result = pilot_status(prepared, receipt, audit, score)
    assert result["matching_label_receipt"] is True
    assert result["prepared_cases"] == result["responses"] == 2
    assert "private-hash" not in str(result) and "private" not in str(result)


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
