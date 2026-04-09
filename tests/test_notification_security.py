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

    def test_sanitize_webhook_headers_removes_host_override(self):
        svc = EnhancedNotificationService()
        headers = {
            "Content-Type": "application/json",
            "Host": "169.254.169.254",
            "Authorization": "Bearer token",
        }
        sanitized = svc._sanitize_webhook_headers(headers)
        assert "Host" not in sanitized
        assert sanitized["Authorization"] == "Bearer token"

    def test_sanitize_webhook_headers_drops_empty_bearer_authorization(self):
        svc = EnhancedNotificationService()
        headers = {"Authorization": "Bearer "}
        sanitized = svc._sanitize_webhook_headers(headers)
        assert "Authorization" not in sanitized
        assert sanitized["Content-Type"] == "application/json"
