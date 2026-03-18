"""Security-focused tests for notification outbound delivery validation."""

from core.notification_service import EnhancedNotificationService


class TestNotificationWebhookValidation:
    """Validate webhook URL hardening rules."""

    def test_accepts_public_https_ip(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://1.1.1.1/webhook")
        assert is_valid is True
        assert error is None

    def test_rejects_non_https_webhook(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("http://1.1.1.1/webhook")
        assert is_valid is False
        assert "HTTPS" in (error or "")

    def test_rejects_embedded_credentials(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://user:pass@example.com/hook")
        assert is_valid is False
        assert "embedded credentials" in (error or "")

    def test_rejects_private_ip_host(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://10.0.0.2/webhook")
        assert is_valid is False
        assert "public address" in (error or "")

    def test_rejects_localhost(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://localhost/hook")
        assert is_valid is False
        assert "public address" in (error or "")
