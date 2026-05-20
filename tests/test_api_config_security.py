"""Security tests for social API configuration persistence."""

import json

from integrations.api_config import SocialAPIManager


def test_social_api_config_ignores_persisted_secrets_and_uses_environment(tmp_path, monkeypatch):
    config_path = tmp_path / "social_apis.json"
    config_path.write_text(
        json.dumps(
            {
                "youtube": {
                    "api_key": "persisted-secret",
                    "requests_per_minute": 10,
                    "requests_per_hour": 20,
                    "requests_per_day": 30,
                    "enabled": False,
                }
            }
        )
    )
    monkeypatch.setenv("YOUTUBE_API_KEY", "env-secret")

    manager = SocialAPIManager(str(config_path))

    config = manager.get_config("youtube")
    assert config is not None
    assert config.api_key == "env-secret"
    assert config.enabled is True
    assert config.requests_per_minute == 10


def test_social_api_config_does_not_persist_secrets(tmp_path):
    config_path = tmp_path / "social_apis.json"
    manager = SocialAPIManager(str(config_path))

    manager.set_api_key(
        "twitter",
        api_key="api-secret",
        secret_key="secret-key",
        access_token="access-token",
        refresh_token="refresh-token",
    )

    saved = json.loads(config_path.read_text())
    assert "api_key" not in saved["twitter"]
    assert "secret_key" not in saved["twitter"]
    assert "access_token" not in saved["twitter"]
    assert "refresh_token" not in saved["twitter"]
