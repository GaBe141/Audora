"""Security tests for notification webhook URL validation."""

import json

import pytest

from core.notification_service import EnhancedNotificationService


class TestWebhookUrlValidation:
    """Validate SSRF protections for outbound webhooks."""

    def test_rejects_non_https_urls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="HTTPS"):
            svc._validate_webhook_url("http://example.com/webhook")

    def test_rejects_localhost_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://localhost/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_private_smtp_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("10.0.0.1", 587)

    def test_allows_private_smtp_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        assert svc._validate_smtp_host("10.0.0.1", 587, allow_private=True) == "10.0.0.1"

    def test_save_config_strips_secrets_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDORA_PERSIST_NOTIFICATION_SECRETS", raising=False)
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "top-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        svc.config["webhook"]["url"] = "https://example.com/hook"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        out = tmp_path / "notification_config.json"
        svc.save_config(str(out))
        saved = json.loads(out.read_text())

        assert "password" not in saved["email"]
        assert "webhook_url" not in saved["slack"]
        assert "webhook_url" not in saved["discord"]
        assert "url" not in saved["webhook"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]

    def test_save_config_can_persist_secrets_when_explicitly_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDORA_PERSIST_NOTIFICATION_SECRETS", "true")
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "top-secret"

        out = tmp_path / "notification_config.json"
        svc.save_config(str(out))
        saved = json.loads(out.read_text())

        assert saved["email"]["password"] == "top-secret"
