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


class TestNotificationConfigSanitization:
    """Ensure sensitive values are not persisted to disk."""

    def test_save_config_redacts_sensitive_fields(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret-password"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer top-secret-token"
        svc.config["sms"]["api_secret"] = "sms-secret"

        output_path = tmp_path / "notification_config.json"
        svc.save_config(path=str(output_path))

        saved_data = output_path.read_text(encoding="utf-8")
        assert "super-secret-password" not in saved_data
        assert "top-secret-token" not in saved_data
        assert "sms-secret" not in saved_data


class TestWebhookHostValidation:
    """Verify SSRF bypass-resistant hostname checks."""

    def test_rejects_numeric_localhost_hostnames(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1.nip.io/webhook")
