"""Security tests for the Dash GUI access gate and settings persistence."""

import importlib
import json

import pytest


@pytest.fixture
def gui_app(monkeypatch):
    """Reload the GUI module with a clean auth-related environment."""
    for env_name in (
        "AUDORA_GUI_TOKEN",
        "AUDORA_GUI_REQUIRE_AUTH",
        "AUDORA_GUI_SECRET_KEY",
        "AUDORA_ALLOW_PLAINTEXT_NOTIFICATION_SECRETS",
    ):
        monkeypatch.delenv(env_name, raising=False)

    app_module = importlib.import_module("gui.app")
    app_module = importlib.reload(app_module)
    app_module.app.server.config.update(TESTING=True)
    return app_module


def test_local_gui_requests_are_allowed_without_token(gui_app):
    client = gui_app.app.server.test_client()

    response = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})

    assert response.status_code == 200


def test_remote_gui_requests_require_token(gui_app):
    client = gui_app.app.server.test_client()

    response = client.get(
        "/",
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
        headers={"Host": "audora.example.com"},
    )

    assert response.status_code == 401
    assert b"remote access is disabled" in response.data


def test_remote_gui_requests_accept_configured_bearer_token(gui_app, monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_TOKEN", "test-token")
    client = gui_app.app.server.test_client()

    response = client.get(
        "/",
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
        headers={"Host": "audora.example.com", "Authorization": "Bearer test-token"},
    )

    assert response.status_code == 200


def test_require_auth_blocks_local_requests_without_token(gui_app, monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AUDORA_GUI_TOKEN", "test-token")
    client = gui_app.app.server.test_client()

    response = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})

    assert response.status_code == 401


def test_notification_config_can_be_saved_without_secrets(tmp_path):
    from core.notification_service import EnhancedNotificationService

    config_path = tmp_path / "notification_config.json"
    svc = EnhancedNotificationService()
    svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
    svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
    svc.config["email"]["password"] = "smtp-secret"
    svc.config["sms"]["api_key"] = "sms-key"
    svc.config["sms"]["api_secret"] = "sms-secret"

    svc.save_config(str(config_path), include_secrets=False)

    saved = json.loads(config_path.read_text())
    assert saved["slack"]["webhook_url"] == ""
    assert saved["discord"]["webhook_url"] == ""
    assert saved["webhook"]["url"] == ""
    assert saved["webhook"]["headers"]["Authorization"] == ""
    assert saved["email"]["password"] == ""
    assert saved["sms"]["api_key"] == ""
    assert saved["sms"]["api_secret"] == ""
