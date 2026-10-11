import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from fva import __main__ as cli
from fva import config, setup
from fva.reasoning.model import OpenAICompatibleClient
from fva.reasoning.routing import ASTRA, JUNIOR, SENIOR


class _Gateway(BaseHTTPRequestHandler):
    calls: list = []
    reply = '{"ok": true}'

    def log_message(self, *a):
        pass

    def _send(self, body: dict):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.calls.append(("GET", self.path, self.headers.get("authorization")))
        self._send({"data": [{"id": "gpt-x"}, {"id": "claude-y"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self.calls.append(("POST", self.path, body["model"]))
        self._send({"choices": [{"message": {"content": self.reply}}]})


@pytest.fixture
def gateway():
    _Gateway.calls = []
    _Gateway.reply = '{"ok": true}'
    server = HTTPServer(("127.0.0.1", 0), _Gateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    monkeypatch.setenv("FVA_CONFIG", str(tmp_path / "fva-config.json"))
    monkeypatch.setenv("FVA_GATEWAY_KEY", "sk-test")


def _setup_args(**kw):
    return SimpleNamespace(**{"url": None, "key_env": None, "junior": None, "senior": None, "astra": None,
                              "no_test": False, **kw})


@pytest.mark.parametrize("suffix", ["", "/", "/v1", "/v1/"])
def test_client_accepts_base_url_with_or_without_v1(gateway, suffix, monkeypatch):
    monkeypatch.setenv("K", "sk-test")
    client = OpenAICompatibleClient("gpt-x", gateway + suffix, key_env="K")
    assert client.list_models() == ["claude-y", "gpt-x"]
    assert client.complete("s", "u") == '{"ok": true}'
    assert [c[1] for c in _Gateway.calls] == ["/v1/models", "/v1/chat/completions"]
    assert _Gateway.calls[0][2] == "Bearer sk-test"


def test_setup_with_flags_tests_models_and_saves_no_key(gateway, cfg_file):
    cfg = setup.run(_setup_args(url=gateway, junior="gpt-x", senior="claude-y"))
    assert cfg == {"client": "gateway", "url": gateway, "key_env": "FVA_GATEWAY_KEY",
                   "models": {"senior": "claude-y", "junior": "gpt-x"}}
    assert config.load() == cfg
    assert "sk-test" not in config.path().read_text()
    assert sorted(c[2] for c in _Gateway.calls if c[0] == "POST") == ["claude-y", "gpt-x"]


def test_setup_interactive_picks_from_listed_models(gateway, cfg_file, monkeypatch):
    answers = iter([gateway, "", "2", ""])  # url, key env (default), senior = #2, no junior
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    cfg = setup.run(_setup_args())
    assert cfg["models"] == {"senior": "gpt-x"}


def test_setup_refuses_a_model_that_does_not_answer_json(gateway, cfg_file):
    _Gateway.reply = "Sure! Here you go."
    with pytest.raises(SystemExit, match="not saved"):
        setup.run(_setup_args(url=gateway, junior="", senior="gpt-x"))
    assert config.load() is None


def _assess_args(**kw):
    return SimpleNamespace(**{"client": "gateway", "model": None, "no_route": False, "astra": None,
                              "dry_run": False, **kw})


def test_gateway_routes_by_tier_with_configured_models(gateway, cfg_file):
    config.save({"client": "gateway", "url": gateway, "key_env": "FVA_GATEWAY_KEY",
                 "models": {"junior": "gpt-x", "senior": "claude-y", "astra": "claude-z"}})
    router = cli._router(_assess_args())
    assert router.routed
    assert {t: router.client(t).model_id for t in (JUNIOR, SENIOR, ASTRA)} == {
        JUNIOR: "gpt-x", SENIOR: "claude-y", ASTRA: "claude-z"}
    assert cli.default_client() == "gateway"


def test_gateway_without_junior_uses_senior_for_everything(gateway, cfg_file):
    config.save({"client": "gateway", "url": gateway, "models": {"senior": "claude-y"}})
    router = cli._router(_assess_args())
    assert not router.routed and router.model_id == "claude-y"


def test_gateway_needs_setup(cfg_file):
    with pytest.raises(SystemExit, match="fva setup"):
        cli._router(_assess_args())


def test_private_source_allows_gateway(cfg_file):
    cli.check_private_source("gateway", None)  # API client: no tools, so no canary needed
