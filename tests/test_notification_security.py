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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_invalid_port(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="invalid port"):
            svc._validate_webhook_url("https://example.com:99999/webhook")

    def test_normalize_timeout_bounds_values(self):
        svc = EnhancedNotificationService()

        assert svc._normalize_timeout("invalid").total == 30
        assert svc._normalize_timeout(-5).total == 1
        assert svc._normalize_timeout(999).total == 120

    def test_sanitize_webhook_headers_blocks_unsafe(self):
        svc = EnhancedNotificationService()
        headers = {
            "Authorization": "Bearer abc",
            "Host": "malicious.example",
            "Connection": "keep-alive",
            "X-Custom": "ok",
            "Invalid": 123,
        }

        sanitized = svc._sanitize_webhook_headers(headers)
        assert sanitized["Content-Type"] == "application/json"
        assert sanitized["Authorization"] == "Bearer abc"
        assert sanitized["X-Custom"] == "ok"
        assert "Host" not in sanitized
        assert "Connection" not in sanitized
        assert "Invalid" not in sanitized
