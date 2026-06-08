"""Security tests for configuration validation."""

import pytest

from core.config import SecureConfig


def configure_spotify_env(monkeypatch, redirect_uri: str) -> None:
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client-id")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", redirect_uri)


class TestSpotifyRedirectValidation:
    """Validate OAuth redirect URI host parsing."""

    def test_accepts_localhost_redirect(self, monkeypatch, tmp_path):
        configure_spotify_env(monkeypatch, "http://127.0.0.1:8888/callback")
        env_file = tmp_path / ".env"
        env_file.write_text("", encoding="utf-8")
        env_file.chmod(0o600)

        config = SecureConfig(env_file=str(env_file)).get_spotify_config()

        assert config["redirect_uri"] == "http://127.0.0.1:8888/callback"

    def test_rejects_prefix_based_lookalike_host(self, monkeypatch, tmp_path):
        configure_spotify_env(monkeypatch, "http://localhost.evil.example/callback")
        env_file = tmp_path / ".env"
        env_file.write_text("", encoding="utf-8")
        env_file.chmod(0o600)

        with pytest.raises(ValueError, match="Invalid redirect URI"):
            SecureConfig(env_file=str(env_file)).get_spotify_config()
