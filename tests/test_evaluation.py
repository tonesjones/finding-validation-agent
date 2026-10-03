import json

import pytest

from fva.__main__ import load_profile, main
from fva.evaluation import preflight
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
