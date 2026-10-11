"""Where FVA finds the Polaris token and the gateway key, and how a user stores or removes them.

Lookup order: the environment variable, then a value entered this session, then the operating system's credential store (Windows Credential
Manager, macOS Keychain, Secret Service on Linux; needs `pip install keyring`), then, for the Polaris token
only, the plain-text file `data/.polaris-token` kept for older setups. Values are never printed, logged,
written to the settings file, or sent anywhere except the service they belong to.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SERVICE = "fva"
POLARIS_ENV = "POLARIS_ACCESS_TOKEN"
POLARIS_FILE = Path("data/.polaris-token")
_SESSION: dict[str, str] = {}  # values the user chose not to save


@dataclass(frozen=True)
class Credential:
    label: str
    env: str
    sent_to: str
    file: Path | None = None


def polaris() -> Credential:
    return Credential("Polaris access token", POLARIS_ENV, "your Polaris server only", POLARIS_FILE)


def gateway(env: str) -> Credential:
    return Credential("Model gateway key", env, "your model gateway only")


def _keyring():
    try:
        import keyring
        from keyring.backends import fail
    except ImportError:
        return None
    return None if isinstance(keyring.get_keyring(), fail.Keyring) else keyring


def store_name() -> str | None:
    """A readable name for the OS credential store, or None when there is none."""
    kr = _keyring()
    if kr is None:
        return None
    name = type(kr.get_keyring()).__module__
    for key, label in (("Windows", "Windows Credential Manager"), ("macOS", "macOS Keychain"),
                       ("SecretService", "Secret Service"), ("kwallet", "KWallet")):
        if key.lower() in name.lower():
            return label
    return "the system credential store"


def source(c: Credential) -> str | None:
    """Where the value would come from: 'environment', 'session', 'credential store', 'file', or None."""
    if os.environ.get(c.env):
        return "environment"
    if c.env in _SESSION:
        return "session"
    kr = _keyring()
    if kr is not None and kr.get_password(SERVICE, c.env):
        return "credential store"
    if c.file is not None and c.file.exists():
        return "file"
    return None


def get(c: Credential) -> str | None:
    where = source(c)
    if where == "environment":
        return os.environ[c.env]
    if where == "session":
        return _SESSION[c.env]
    if where == "credential store":
        return _keyring().get_password(SERVICE, c.env)
    if where == "file":
        return c.file.read_text(encoding="utf-8").strip() or None
    return None


def save(c: Credential, value: str, where: str) -> None:
    """where: 'session' (this process only), 'credential store', or 'file' (Polaris token only)."""
    if where == "session":
        _SESSION[c.env] = value
    elif where == "credential store":
        kr = _keyring()
        if kr is None:
            raise SystemExit("no credential store available; `pip install keyring`")
        kr.set_password(SERVICE, c.env, value)
    elif where == "file":
        if c.file is None:
            raise ValueError(f"{c.label} cannot be saved to a file")
        c.file.parent.mkdir(parents=True, exist_ok=True)
        c.file.write_text(value, encoding="utf-8")


def forget(c: Credential) -> list[str]:
    """Remove the saved copies FVA made. The environment variable belongs to the user and is left alone."""
    removed = []
    kr = _keyring()
    if kr is not None and kr.get_password(SERVICE, c.env):
        kr.delete_password(SERVICE, c.env)
        removed.append(store_name())
    if c.file is not None and c.file.exists():
        c.file.unlink()
        removed.append(str(c.file))
    return removed


def describe(c: Credential) -> str:
    where = source(c)
    text = {"environment": f"set in the environment variable {c.env} (not saved by FVA)",
            "session": "kept in memory for this session only (not saved)",
            "credential store": f"saved in {store_name()} (encrypted by your OS, under '{SERVICE}/{c.env}')",
            "file": f"saved in plain text in {c.file} (git-ignored; consider moving it to the credential store)",
            None: "not set"}[where]
    return f"{c.label}: {text}. Sent to {c.sent_to}."


def prompt(c: Credential) -> str:
    """Ask for the value with hidden input and let the user choose where, if anywhere, it is kept."""
    import getpass
    value = getpass.getpass(f"{c.label} (input hidden): ").strip()
    if not value:
        raise SystemExit(f"{c.label} is required")
    options = [("session", "This session only. Nothing is saved; you paste it again next time.")]
    if store_name():
        options.insert(0, ("credential store", f"{store_name()}, encrypted by your OS. Remove any time with "
                                               "`python -m fva credentials --forget`."))
    if c.file is not None:
        options.append(("file", f"Plain text in {c.file} (git-ignored). Anyone with access to this folder can read it."))
    print(f"Where should FVA keep the {c.label.lower()}?")
    for i, (_, text) in enumerate(options, 1):
        print(f"  {i}. {text}")
    if not store_name():
        print("  (Install `keyring` with `pip install keyring` to use your OS credential store.)")
    answer = input("Choice [1]: ").strip() or "1"
    where = options[int(answer) - 1][0] if answer.isdigit() and 1 <= int(answer) <= len(options) else "session"
    save(c, value, where)
    print(f"  {describe(c)}")
    return value


def ensure(c: Credential) -> None:
    """Tell the user where the value comes from, or ask for it."""
    if source(c):
        print(f"  {describe(c)}")
    else:
        prompt(c)


EXPLAINER = """How FVA handles your credentials:
  - The Polaris token and the gateway key are only sent to Polaris and to your gateway.
  - They are never printed, logged, written to the settings file, or sent to a model.
  - You choose where each is kept: your OS credential store (encrypted), this session only, or an
    environment variable you set yourself. FVA reads an environment variable first.
  - `python -m fva credentials` shows where each one is; `--forget` removes what FVA saved."""
