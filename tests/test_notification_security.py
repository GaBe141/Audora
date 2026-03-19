"""Security-focused tests for notification webhook validation."""

from core.notification_service import EnhancedNotificationService


class TestWebhookUrlValidation:
    """Validate outbound webhook URL restrictions."""

    def test_rejects_non_https_webhook_urls(self):
        service = EnhancedNotificationService()
        is_valid, reason = service._validate_webhook_url("http://hooks.slack.com/services/a/b/c")
        assert is_valid is False
        assert "HTTPS" in reason

    def test_rejects_localhost_targets(self):
        service = EnhancedNotificationService()
        is_valid, reason = service._validate_webhook_url("https://localhost/webhook")
        assert is_valid is False
        assert "not allowed" in reason

    def test_rejects_private_ip_targets(self):
        service = EnhancedNotificationService()
        is_valid, reason = service._validate_webhook_url("https://10.0.0.12/webhook")
        assert is_valid is False
        assert "not allowed" in reason

    def test_accepts_public_https_targets(self):
        service = EnhancedNotificationService()
        is_valid, _ = service._validate_webhook_url("https://hooks.slack.com/services/a/b/c")
        assert is_valid is True
