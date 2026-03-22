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


class TestSmtpHostValidation:
    """Validate SSRF protections for outbound SMTP connections."""

    def test_rejects_localhost_smtp_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_server("localhost")

    def test_rejects_private_smtp_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_server("10.0.0.1")

    def test_allows_private_smtp_target_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        assert svc._validate_smtp_server("10.0.0.1", allow_private=True) == "10.0.0.1"
