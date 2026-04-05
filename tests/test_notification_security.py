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


class TestWebhookHttpTimeouts:
    """Validate bounded outbound timeout handling."""

    def test_timeout_clamps_to_maximum(self):
        svc = EnhancedNotificationService()
        timeout = svc._get_http_timeout(1000)
        assert timeout.total == 120
        assert timeout.connect == 10
        assert timeout.sock_connect == 10
        assert timeout.sock_read == 120

    def test_timeout_clamps_to_minimum(self):
        svc = EnhancedNotificationService()
        timeout = svc._get_http_timeout(0)
        assert timeout.total == 1
        assert timeout.connect == 1
        assert timeout.sock_connect == 1
        assert timeout.sock_read == 1

    def test_timeout_uses_default_for_invalid_values(self):
        svc = EnhancedNotificationService()
        timeout = svc._get_http_timeout("not-a-number")
        assert timeout.total == 30
        assert timeout.connect == 10
        assert timeout.sock_connect == 10
        assert timeout.sock_read == 30
