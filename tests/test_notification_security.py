"""Security tests for notification webhook URL validation."""

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

    def test_private_webhook_override_is_ignored(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is False

    def test_save_config_redacts_sensitive_values(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer abc123"
        svc.config["webhook"]["headers"]["X-Api-Key"] = "apikey"

        out_file = tmp_path / "notification_config.json"
        svc.save_config(path=str(out_file))

        persisted = __import__("json").loads(out_file.read_text(encoding="utf-8"))
        assert persisted["email"]["password"] == ""
        assert persisted["sms"]["api_key"] == ""
        assert persisted["sms"]["api_secret"] == ""
        assert persisted["webhook"]["headers"]["Authorization"] == ""
        assert persisted["webhook"]["headers"]["X-Api-Key"] == ""
