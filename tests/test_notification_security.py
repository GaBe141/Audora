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

    def test_http_timeout_is_bounded(self):
        svc = EnhancedNotificationService()
        timeout = svc._http_timeout(9999)
        assert timeout.total == 120

        timeout = svc._http_timeout(-10)
        assert timeout.total == 1

    def test_header_sanitization_blocks_crlf(self):
        svc = EnhancedNotificationService()
        headers = {
            "X-Good": "ok",
            "X-Bad": "evil\r\nInjected: yes",
            "Bad\r\nKey": "value",
        }
        sanitized = svc._sanitize_webhook_headers(headers)
        assert sanitized["X-Good"] == "ok"
        assert "X-Bad" not in sanitized
        assert "Bad\r\nKey" not in sanitized
        assert sanitized["Content-Type"] == "application/json"
