"""Security tests for configuration validation."""

import pytest

from core.config import SecureConfig


def _set_required_spotify_env(monkeypatch, redirect_uri: str) -> None:
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client-id")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", redirect_uri)


def test_spotify_redirect_uri_allows_loopback_hosts(monkeypatch, tmp_path):
    _set_required_spotify_env(monkeypatch, "http://localhost:8888/callback")
    config = SecureConfig(env_file=str(tmp_path / ".env"))

    spotify_config = config.get_spotify_config()

    assert spotify_config["redirect_uri"] == "http://localhost:8888/callback"


def test_spotify_redirect_uri_rejects_prefix_bypass(monkeypatch, tmp_path):
    _set_required_spotify_env(monkeypatch, "http://localhost.evil.example/callback")
    config = SecureConfig(env_file=str(tmp_path / ".env"))

    with pytest.raises(ValueError, match="Invalid redirect URI"):
        config.get_spotify_config()
