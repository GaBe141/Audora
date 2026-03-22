"""Security-focused tests for configuration validation."""

import pytest

from core.config import SecureConfig


def _build_config(tmp_path, monkeypatch, redirect_uri: str) -> SecureConfig:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", redirect_uri)
    return SecureConfig(env_file=str(env_file))


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://localhost:8888/callback",
        "http://127.0.0.1:8888/callback",
        "http://[::1]:8888/callback",
    ],
)
def test_spotify_redirect_uri_accepts_local_loopback_hosts(tmp_path, monkeypatch, redirect_uri):
    config = _build_config(tmp_path, monkeypatch, redirect_uri)
    loaded = config.get_spotify_config()
    assert loaded["redirect_uri"] == redirect_uri


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://localhost.evil.com/callback",
        "http://127.0.0.1.evil.com/callback",
        "http://localhost@evil.com/callback",
        "javascript://localhost/callback",
        "ftp://localhost/callback",
    ],
)
def test_spotify_redirect_uri_rejects_host_spoof_and_invalid_schemes(
    tmp_path, monkeypatch, redirect_uri
):
    config = _build_config(tmp_path, monkeypatch, redirect_uri)
    with pytest.raises(ValueError):
        config.get_spotify_config()
