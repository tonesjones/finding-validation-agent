import pytest

from fva import __main__ as cli
from fva import credentials


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, name):
        return self.store.get((service, name))

    def set_password(self, service, name, value):
        self.store[(service, name)] = value

    def delete_password(self, service, name):
        del self.store[(service, name)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("POLARIS_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("FVA_GATEWAY_KEY", raising=False)
    monkeypatch.setenv("FVA_CONFIG", str(tmp_path / "cfg.json"))
    monkeypatch.setattr(credentials, "_SESSION", {})
    kr = FakeKeyring()
    monkeypatch.setattr(credentials, "_keyring", lambda: kr)
    monkeypatch.setattr(credentials, "store_name", lambda: "Windows Credential Manager")
    return kr


def _prompt(monkeypatch, value, choice):
    monkeypatch.setattr("getpass.getpass", lambda _: value)
    monkeypatch.setattr("builtins.input", lambda _: choice)


def test_environment_wins_and_is_never_saved(env, monkeypatch):
    monkeypatch.setenv("POLARIS_ACCESS_TOKEN", "from-env")
    env.set_password("fva", "POLARIS_ACCESS_TOKEN", "from-store")
    c = credentials.polaris()
    assert credentials.get(c) == "from-env"
    assert "not saved by FVA" in credentials.describe(c)


def test_store_choice_saves_to_os_store_only(env, monkeypatch, capsys):
    _prompt(monkeypatch, "secret-1", "1")
    c = credentials.polaris()
    credentials.prompt(c)
    assert env.store == {("fva", "POLARIS_ACCESS_TOKEN"): "secret-1"}
    assert not credentials.POLARIS_FILE.exists()
    assert "Windows Credential Manager" in credentials.describe(c)
    assert "secret-1" not in capsys.readouterr().out


def test_session_choice_saves_nothing(env, monkeypatch):
    _prompt(monkeypatch, "secret-2", "2")
    c = credentials.gateway("FVA_GATEWAY_KEY")
    credentials.prompt(c)
    assert credentials.get(c) == "secret-2"
    assert env.store == {} and credentials.source(c) == "session"


def test_gateway_key_has_no_plain_text_file_option(env, monkeypatch):
    _prompt(monkeypatch, "secret-3", "3")  # the gateway key has two options; an out-of-range answer keeps it in memory
    c = credentials.gateway("FVA_GATEWAY_KEY")
    credentials.prompt(c)
    assert env.store == {} and credentials.source(c) == "session"
    assert not credentials.POLARIS_FILE.parent.exists()


def test_forget_removes_store_and_file(env, monkeypatch, capsys):
    env.set_password("fva", "POLARIS_ACCESS_TOKEN", "a")
    credentials.POLARIS_FILE.parent.mkdir()
    credentials.POLARIS_FILE.write_text("b")
    cli.main(["credentials", "--forget", "polaris"])
    out = capsys.readouterr().out
    assert env.store == {} and not credentials.POLARIS_FILE.exists()
    assert "removed from Windows Credential Manager, data" in out
    assert "Polaris access token: not set" in out


def test_credentials_command_never_prints_values(env, monkeypatch, capsys):
    env.set_password("fva", "POLARIS_ACCESS_TOKEN", "tok-XYZ")
    monkeypatch.setenv("FVA_GATEWAY_KEY", "key-XYZ")
    cli.main(["credentials"])
    out = capsys.readouterr().out
    assert "XYZ" not in out
    assert "Windows Credential Manager" in out and "environment variable FVA_GATEWAY_KEY" in out
