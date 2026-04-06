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


class TestSensitiveConfigPersistence:
    """Validate that persisted config excludes secrets."""

    def test_save_config_redacts_sensitive_fields(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["email"]["username"] = "smtp-user"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/a/b/c"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/abc"
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {
            "Content-Type": "application/json",
            "Authorization": "Bearer should-not-be-persisted",
            "X-Api-Key": "should-not-be-persisted",
        }
        svc.config["sms"]["api_key"] = "sms-api-key"
        svc.config["sms"]["api_secret"] = "sms-api-secret"

        output_path = tmp_path / "notification_config.json"
        svc.save_config(str(output_path))
        persisted = json.loads(output_path.read_text(encoding="utf-8"))

        # SMTP credentials should only come from environment variables.
        assert "username" not in persisted["email"]
        assert "password" not in persisted["email"]

        # Webhook endpoints are sensitive and must not be stored on disk.
        assert "webhook_url" not in persisted["slack"]
        assert "webhook_url" not in persisted["discord"]
        assert "url" not in persisted["webhook"]

        # Auth secrets must not be persisted in webhook headers.
        headers = persisted["webhook"]["headers"]
        assert headers == {"Content-Type": "application/json"}
        assert "Authorization" not in headers
        assert "X-Api-Key" not in headers

        # SMS provider secrets must not be persisted.
        assert "api_key" not in persisted["sms"]
        assert "api_secret" not in persisted["sms"]
