"""Security tests for social API configuration persistence."""

import json
from pathlib import Path

from integrations.api_config import SocialAPIManager


def test_social_api_config_does_not_persist_credentials(tmp_path: Path):
    config_path = tmp_path / "social_apis.json"
    manager = SocialAPIManager(str(config_path))

    manager.set_api_key(
        "youtube",
        api_key="youtube-secret",
        secret_key="unused-secret",
        access_token="access-secret",
        refresh_token="refresh-secret",
    )

    saved_text = config_path.read_text(encoding="utf-8")
    saved = json.loads(saved_text)

    assert "secret" not in saved_text
    assert "api_key" not in saved["youtube"]
    assert "secret_key" not in saved["youtube"]
    assert "access_token" not in saved["youtube"]
    assert "refresh_token" not in saved["youtube"]
    assert saved["youtube"]["enabled"] is True


def test_social_api_config_loads_credentials_from_environment(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "social_apis.json"
    config_path.write_text(
        json.dumps(
            {
                "youtube": {
                    "requests_per_minute": 100,
                    "requests_per_hour": 10000,
                    "requests_per_day": 1000000,
                    "enabled": False,
                    "last_error": "",
                    "error_count": 0,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("YOUTUBE_API_KEY", "env-secret")

    manager = SocialAPIManager(str(config_path))
    youtube = manager.get_config("youtube")

    assert youtube is not None
    assert youtube.api_key == "env-secret"
    assert youtube.enabled is True


def test_social_api_config_ignores_legacy_credentials_from_disk(tmp_path: Path):
    config_path = tmp_path / "social_apis.json"
    config_path.write_text(
        json.dumps(
            {
                "youtube": {
                    "api_key": "legacy-secret",
                    "access_token": "legacy-token",
                    "requests_per_minute": 100,
                    "requests_per_hour": 10000,
                    "requests_per_day": 1000000,
                    "enabled": True,
                    "last_error": "",
                    "error_count": 0,
                }
            }
        ),
        encoding="utf-8",
    )

    manager = SocialAPIManager(str(config_path))
    youtube = manager.get_config("youtube")

    assert youtube is not None
    assert youtube.api_key == ""
    assert youtube.access_token == ""
    assert youtube.enabled is False
