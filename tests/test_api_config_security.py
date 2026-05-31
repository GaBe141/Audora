"""Security tests for social API configuration persistence."""

import json

from integrations.api_config import SocialAPIManager


def test_social_api_config_does_not_persist_credentials(tmp_path):
    config_path = tmp_path / "social_apis.json"
    manager = SocialAPIManager(str(config_path))

    manager.set_api_key(
        "reddit",
        api_key="client-id",
        secret_key="client-secret",
        access_token="access-token",
        refresh_token="refresh-token",
    )

    saved = json.loads(config_path.read_text())
    assert "api_key" not in saved["reddit"]
    assert "secret_key" not in saved["reddit"]
    assert "access_token" not in saved["reddit"]
    assert "refresh_token" not in saved["reddit"]


def test_social_api_credentials_load_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("REDDIT_CLIENT_ID", "client-id")
    monkeypatch.setenv("REDDIT_CLIENT_SECRET", "client-secret")

    manager = SocialAPIManager(str(tmp_path / "social_apis.json"))
    reddit = manager.get_config("reddit")

    assert reddit is not None
    assert reddit.api_key == "client-id"
    assert reddit.secret_key == "client-secret"
    assert reddit.enabled is True
