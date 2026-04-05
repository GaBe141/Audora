"""Security tests for notification config persistence behavior."""

import json

from core.notification_service import EnhancedNotificationService


def test_save_config_redacts_secrets_by_default(tmp_path, monkeypatch):
    """Secret values should not be persisted unless explicitly enabled."""
    monkeypatch.delenv("AUDORA_ALLOW_PERSIST_NOTIFICATION_SECRETS", raising=False)

    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "super-secret"
    svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/AAA/BBB/CCC"
    svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/2"
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer top-secret"
    svc.config["sms"]["api_key"] = "sms-key"
    svc.config["sms"]["api_secret"] = "sms-secret"

    save_path = tmp_path / "notification_config.json"
    svc.save_config(str(save_path))

    saved = json.loads(save_path.read_text())
    assert saved["email"]["password"] == ""
    assert saved["slack"]["webhook_url"] == ""
    assert saved["discord"]["webhook_url"] == ""
    assert saved["webhook"]["url"] == ""
    assert saved["webhook"]["headers"]["Authorization"] == ""
    assert saved["sms"]["api_key"] == ""
    assert saved["sms"]["api_secret"] == ""


def test_save_config_can_persist_secrets_with_explicit_opt_in(tmp_path, monkeypatch):
    """Persistence of secrets is allowed only through explicit opt-in env var."""
    monkeypatch.setenv("AUDORA_ALLOW_PERSIST_NOTIFICATION_SECRETS", "true")

    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "super-secret"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer top-secret"

    save_path = tmp_path / "notification_config.json"
    svc.save_config(str(save_path))

    saved = json.loads(save_path.read_text())
    assert saved["email"]["password"] == "super-secret"
    assert saved["webhook"]["headers"]["Authorization"] == "Bearer top-secret"
