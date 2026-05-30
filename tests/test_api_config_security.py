"""Security tests for social API configuration persistence."""

import json

from integrations.api_config import SocialAPIManager


def test_social_api_credentials_are_not_persisted(tmp_path):
    config_file = tmp_path / "social_apis.json"
    manager = SocialAPIManager(config_file=str(config_file))

    manager.set_api_key(
        "youtube",
        api_key="youtube-secret",
        secret_key="unused-secret",
        access_token="access-secret",
        refresh_token="refresh-secret",
    )

    saved = json.loads(config_file.read_text(encoding="utf-8"))
    assert "api_key" not in saved["youtube"]
    assert "secret_key" not in saved["youtube"]
    assert "access_token" not in saved["youtube"]
    assert "refresh_token" not in saved["youtube"]


def test_social_api_credentials_load_from_environment(tmp_path, monkeypatch):
    config_file = tmp_path / "social_apis.json"
    monkeypatch.setenv("YOUTUBE_API_KEY", "env-youtube-key")

    manager = SocialAPIManager(config_file=str(config_file))
    config = manager.get_config("youtube")

    assert config is not None
    assert config.api_key == "env-youtube-key"
    assert config.enabled is True


def test_legacy_persisted_credentials_are_ignored(tmp_path, monkeypatch):
    config_file = tmp_path / "social_apis.json"
    config_file.write_text(
        json.dumps(
            {
                "youtube": {
                    "api_key": "legacy-secret",
                    "requests_per_minute": 100,
                    "requests_per_hour": 1000,
                    "requests_per_day": 10000,
                    "enabled": True,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("YOUTUBE_API_KEY", raising=False)

    manager = SocialAPIManager(config_file=str(config_file))
    config = manager.get_config("youtube")

    assert config is not None
    assert config.api_key == ""
