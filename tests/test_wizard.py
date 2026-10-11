import json
import subprocess

import pytest

from fva import config, wizard


def _text(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


class FakePolaris:
    def __init__(self):
        self.calls = []

    def call(self, tool, **args):
        self.calls.append((tool, args))
        if tool == "get_portfolio_id":
            return _text({"data": {"portfolioId": "pf-1"}})
        if tool == "get_portfolio_projects":
            return _text({"_items": [{"id": "p-b", "name": "Billing"}, {"id": "p-a", "name": "Accounts"}]})
        if tool == "get_branches":
            return _text({"_items": [{"id": "b-main", "name": "main"}]})
        if tool == "list_issues":
            return _text({"data": {"_items": []}})
        raise AssertionError(tool)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FVA_CONFIG", raising=False)
    monkeypatch.setenv("POLARIS_ACCESS_TOKEN", "tok")
    return tmp_path


def _answers(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _: next(it))


def test_polaris_step_picks_project_and_branch_and_exports(workdir, monkeypatch):
    fake = FakePolaris()
    _answers(monkeypatch, "https://polaris.example", "1", "1")  # url, Accounts (sorted first), main
    cfg = wizard.polaris_step({}, make_client=lambda: fake)
    p = cfg["polaris"]
    assert (p["project"], p["project_name"], p["branch"]) == ("p-a", "Accounts", "b-main")
    assert ("list_issues", {"projectId": "p-a", "branchId": "b-main", "first": 10, "includeOccurrenceProperties": True,
                            "includeContext": True, "includeTriageProperties": True}) in fake.calls
    assert (workdir / p["export"] / "page-0001.json").exists()
    assert config.load()["polaris"] == p


def test_polaris_step_reuses_a_saved_export(workdir, monkeypatch):
    (workdir / "exp").mkdir()
    _answers(monkeypatch, "")
    cfg = {"polaris": {"export": "exp", "project": "p-a"}}
    assert wizard.polaris_step(cfg, make_client=lambda: pytest.fail("no Polaris call")) == cfg


def test_source_step_builds_a_valid_profile(workdir, monkeypatch):
    app = workdir / "shop"
    (app / "src").mkdir(parents=True)
    (app / "package.json").write_text('{"main": "server.js"}')
    (app / "server.js").write_text("")
    (app / "src/main.ts").write_text("")
    subprocess.run(["git", "init", "-q", str(app)], check=True)
    subprocess.run(["git", "-C", str(app), "-c", "user.email=a@b", "-c", "user.name=a", "add", "."], check=True)
    subprocess.run(["git", "-C", str(app), "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "x"],
                   check=True)
    _answers(monkeypatch, str(app), "Shop", "", "")  # path, name, entrypoints (guessed), tests don't ship
    cfg = wizard.source_step({})
    profile = json.loads((workdir / cfg["source"]["profile"]).read_text())
    assert profile["name"] == "Shop" and profile["language_packs"] == ["node"]
    assert profile["entrypoints"] == ["server.js", "src/main.ts"]
    assert len(profile["source_commit"]) == 40


def test_run_step_runs_smoke_then_assess_triage_report(workdir, monkeypatch):
    calls = []
    _answers(monkeypatch, "", "", "")  # quick check yes, start yes, full run yes
    cfg = {"client": "gateway", "polaris": {"export": "exp", "project_name": "Accounts"},
           "source": {"path": "shop", "profile": "p.json"}}
    run_dir = wizard.run_step(cfg, cli_main=calls.append, open_report=False)
    assert [c[0] for c in calls] == ["assess", "assess", "triage", "report"]
    assert "--private-source" in calls[0] and calls[0][-4:] == ["--limit", "1", "--out", f"{run_dir}-smoke"]
    assert calls[1][-2:] == ["--out", str(run_dir)]


def test_no_arguments_starts_the_wizard(monkeypatch):
    from fva import __main__ as cli
    monkeypatch.setattr(wizard, "main", lambda: "started")
    assert cli.main([]) == "started"
