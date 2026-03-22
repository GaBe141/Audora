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


class TestSmtpTargetValidation:
    """Validate SSRF protections for outbound SMTP targets."""

    def test_rejects_localhost_smtp_target(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="localhost"):
            svc._validate_outbound_host("localhost", 587, target_name="SMTP server")

    def test_rejects_private_ip_smtp_target_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_outbound_host("10.0.0.2", 587, target_name="SMTP server")

    def test_allows_private_smtp_target_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        assert svc._validate_outbound_host(
            "10.0.0.2", 587, allow_private=True, target_name="SMTP server"
        ) == ("10.0.0.2", 587)
