import argparse

import pytest

import fva.__main__ as cli


def args(**kw):
    base = dict(client="codex", model=None, dry_run=False, route=False, astra=None)
    return argparse.Namespace(**{**base, **kw})


@pytest.fixture
def made(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_client", lambda name, model: calls.append((name, model)) or type("C", (), {"model_id": f"{name}:{model}"})())
    return calls


def test_codex_defaults_to_sol_only(made, monkeypatch):
    monkeypatch.delenv("FVA_MODEL_SENIOR", raising=False)
    r = cli._router(args())
    assert not r.routed and made == [("codex", "gpt-6-sol")]


def test_explicit_model_wins(made):
    cli._router(args(model="gpt-6-luna"))
    assert made == [("codex", "gpt-6-luna")]


def test_route_builds_both_tiers(made, monkeypatch):
    monkeypatch.delenv("FVA_MODEL_JUNIOR", raising=False)
    monkeypatch.delenv("FVA_MODEL_SENIOR", raising=False)
    r = cli._router(args(route=True))
    assert r.routed and [m for _, m in made] == ["gpt-6-luna", "gpt-6-sol"]


@pytest.mark.parametrize("kw", [dict(route=True, model="x"), dict(route=True, client="claude-code"), dict(astra=["id"])])
def test_invalid_combinations(made, kw):
    with pytest.raises(SystemExit):
        cli._router(args(**kw))
