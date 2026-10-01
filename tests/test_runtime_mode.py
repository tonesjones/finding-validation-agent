import pytest

from fva.runtime_mode import DEFAULT_MODE, RuntimeModeError, check
from fva.schemas import RuntimeMode


def test_default_is_dast_evidence():
    """Default mode is dast-evidence."""
    assert DEFAULT_MODE == RuntimeMode.dast_evidence


def test_none_returns_default():
    """None mode returns DEFAULT_MODE."""
    assert check(None) == RuntimeMode.dast_evidence


def test_enum_passthrough():
    """RuntimeMode enum values are returned as-is."""
    assert check(RuntimeMode.none) == RuntimeMode.none
    assert check(RuntimeMode.dast_evidence) == RuntimeMode.dast_evidence
    assert check(RuntimeMode.live_localhost, "http://localhost") == RuntimeMode.live_localhost


def test_string_conversion():
    """String values are converted to RuntimeMode."""
    assert check("none") == RuntimeMode.none
    assert check("dast-evidence") == RuntimeMode.dast_evidence


def test_live_localhost_accepts_valid_urls():
    """live-localhost accepts localhost, 127.0.0.1, and ::1."""
    assert check(RuntimeMode.live_localhost, "http://localhost:3000") == RuntimeMode.live_localhost
    assert check(RuntimeMode.live_localhost, "http://127.0.0.1:3000") == RuntimeMode.live_localhost
    assert check(RuntimeMode.live_localhost, "http://[::1]:3000") == RuntimeMode.live_localhost
    # Also test without port
    assert check(RuntimeMode.live_localhost, "http://localhost") == RuntimeMode.live_localhost


def test_live_localhost_rejects_none_url():
    """live-localhost requires target_url."""
    with pytest.raises(RuntimeModeError, match="live-localhost mode requires target_url"):
        check(RuntimeMode.live_localhost, None)


def test_live_localhost_rejects_remote_hosts():
    """live-localhost rejects non-localhost hostnames."""
    with pytest.raises(RuntimeModeError, match="live-localhost requires"):
        check(RuntimeMode.live_localhost, "https://example.com")

    with pytest.raises(RuntimeModeError, match="live-localhost requires"):
        check(RuntimeMode.live_localhost, "http://localhost.evil.com")


def test_live_localhost_rejects_userinfo():
    """live-localhost rejects URLs with userinfo."""
    with pytest.raises(RuntimeModeError, match="cannot contain userinfo"):
        check(RuntimeMode.live_localhost, "http://user@localhost:3000")

    with pytest.raises(RuntimeModeError, match="cannot contain userinfo"):
        check(RuntimeMode.live_localhost, "http://user:pass@localhost:3000")


def test_other_modes_ignore_target_url():
    """Non-live-localhost modes ignore target_url."""
    assert check(RuntimeMode.none, "https://example.com") == RuntimeMode.none
    assert check(RuntimeMode.dast_evidence, "https://example.com") == RuntimeMode.dast_evidence


def test_unknown_mode_string_raises():
    """Unknown mode string raises ValueError."""
    with pytest.raises(RuntimeModeError, match="unknown runtime mode"):
        check("invalid-mode")


def test_string_live_localhost_validation():
    """String "live-localhost" is converted and validated correctly."""
    assert check("live-localhost", "http://localhost:3000") == RuntimeMode.live_localhost

    with pytest.raises(RuntimeModeError, match="live-localhost mode requires target_url"):
        check("live-localhost", None)

    with pytest.raises(RuntimeModeError, match="live-localhost requires"):
        check("live-localhost", "https://example.com")


def test_live_localhost_rejects_non_http_scheme():
    with pytest.raises(RuntimeModeError):
        check("live-localhost", "file:///etc/passwd")
