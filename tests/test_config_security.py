"""Security tests for configuration and credential handling."""

import json
import os

from core.config import SecureConfig
from integrations.api_config import DEFAULT_CONFIG_FILE, SocialAPIManager


def test_secure_config_does_not_override_existing_environment(monkeypatch, tmp_path):
    """Runtime-provided secrets should take precedence over local .env files."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SPOTIFY_CLIENT_ID=file_client_id",
                "SPOTIFY_CLIENT_SECRET=file_client_secret",
                "SPOTIFY_REDIRECT_URI=http://127.0.0.1:8888/callback",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "runtime_client_id")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "runtime_client_secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:9999/callback")

    config = SecureConfig(env_file=str(env_file)).get_spotify_config()

    assert config["client_id"] == "runtime_client_id"
    assert config["client_secret"] == "runtime_client_secret"
    assert config["redirect_uri"] == "http://127.0.0.1:9999/callback"


def test_social_api_manager_uses_ignored_secret_config_path_by_default():
    assert DEFAULT_CONFIG_FILE == "config/social_apis_config.json"


def test_social_api_manager_respects_environment_config_override(monkeypatch, tmp_path):
    config_file = tmp_path / "social_apis.local.json"
    config_file.write_text(
        json.dumps({"youtube": {"api_key": "test-key", "enabled": True}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("AUDORA_SOCIAL_API_CONFIG", str(config_file))

    manager = SocialAPIManager()

    assert manager.config_file == config_file
    assert manager.get_config("youtube").api_key == "test-key"


def test_social_api_manager_writes_restrictive_permissions(tmp_path):
    config_file = tmp_path / "social_apis_config.json"
    manager = SocialAPIManager(config_file=str(config_file))

    assert config_file.exists()
    if os.name != "nt":
        assert oct(config_file.stat().st_mode)[-3:] == "600"
