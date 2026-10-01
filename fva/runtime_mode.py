"""Runtime mode gate: live probing only against a localhost http(s) target; default is DAST evidence."""
from __future__ import annotations

from urllib.parse import urlsplit

from fva.schemas import RuntimeMode

DEFAULT_MODE = RuntimeMode.dast_evidence
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class RuntimeModeError(ValueError):
    pass


def default_for(scanner_mix) -> RuntimeMode:
    """DAST evidence only when the scan has DAST; SAST+SCA-only scans (e.g. non-web apps) are static-only."""
    return RuntimeMode.dast_evidence if "dast" in set(scanner_mix) else RuntimeMode.none


def check(mode: RuntimeMode | str | None, target_url: str | None = None) -> RuntimeMode:
    if mode is None:
        return DEFAULT_MODE
    if isinstance(mode, str):
        try:
            mode = RuntimeMode(mode)
        except ValueError:
            raise RuntimeModeError(f"unknown runtime mode: {mode!r}") from None
    if mode is RuntimeMode.live_localhost:
        if target_url is None:
            raise RuntimeModeError("live-localhost mode requires target_url")
        u = urlsplit(target_url)
        if u.scheme not in ("http", "https"):
            raise RuntimeModeError(f"target_url must be http(s): {target_url!r}")
        if u.username is not None or u.password is not None:
            raise RuntimeModeError(f"target_url cannot contain userinfo: {target_url!r}")
        if u.hostname not in _LOCAL_HOSTS:
            raise RuntimeModeError(f"live-localhost requires one of {_LOCAL_HOSTS}; got {u.hostname!r}")
    return mode
