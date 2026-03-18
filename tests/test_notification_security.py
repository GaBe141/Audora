"""Security-focused tests for notification outbound URL validation."""

from core.notification_service import EnhancedNotificationService


class TestNotificationUrlValidation:
    """Validate SSRF protections for outbound webhooks."""

    def test_rejects_non_https_urls(self):
        svc = EnhancedNotificationService()
        is_safe, reason = svc._is_safe_outbound_url("http://example.com/webhook")
        assert is_safe is False
        assert "HTTPS" in reason

    def test_rejects_localhost_and_private_ips(self):
        svc = EnhancedNotificationService()
        assert svc._is_safe_outbound_url("https://localhost/hook")[0] is False
        assert svc._is_safe_outbound_url("https://127.0.0.1/hook")[0] is False
        assert svc._is_safe_outbound_url("https://10.0.0.5/hook")[0] is False

    def test_allows_public_https_ip(self):
        svc = EnhancedNotificationService()
        is_safe, reason = svc._is_safe_outbound_url("https://8.8.8.8/webhook")
        assert is_safe is True
        assert reason == ""
