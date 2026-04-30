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


class TestNotificationConfigPersistence:
    """Validate secret material is not persisted to notification config."""

    def test_save_config_omits_sensitive_values(self, tmp_path):
        config_path = tmp_path / "notification_config.json"
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-token"

        svc.save_config(str(config_path))

        saved_config = json.loads(config_path.read_text(encoding="utf-8"))
        assert "password" not in saved_config["email"]
        assert "api_key" not in saved_config["sms"]
        assert "api_secret" not in saved_config["sms"]
        assert "Authorization" not in saved_config["webhook"]["headers"]
        assert saved_config["email"]["smtp_server"] == svc.config["email"]["smtp_server"]
