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
    """Validate SSRF protections for SMTP notification targets."""

    def test_rejects_localhost_smtp_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("localhost", 587)

    def test_rejects_private_smtp_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_target("10.0.0.1", 587)

    def test_allows_private_smtp_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        assert svc._validate_smtp_target("10.0.0.1", 587, allow_private=True) == (
            "10.0.0.1",
            587,
        )

    def test_rejects_invalid_smtp_ports(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="between 1 and 65535"):
            svc._validate_smtp_target("example.com", 0, allow_private=True)
