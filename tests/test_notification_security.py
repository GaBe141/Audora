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
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=True)

    def test_private_webhook_env_bypass_is_ignored(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is False

    def test_save_config_scrubs_notification_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/a/b/c"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/token"
        svc.config["webhook"]["url"] = "https://example.com/hook"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret-token"
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert saved["slack"]["webhook_url"] == ""
        assert saved["discord"]["webhook_url"] == ""
        assert saved["webhook"]["url"] == ""
        assert saved["webhook"]["headers"]["Authorization"] == ""
        assert saved["email"]["password"] == ""
        assert saved["sms"]["api_key"] == ""
        assert saved["sms"]["api_secret"] == ""
