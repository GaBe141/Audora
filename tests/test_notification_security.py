"""Security-focused tests for webhook URL validation in notification service."""

import asyncio

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


class TestNotificationWebhookValidation:
    """Validate URL hardening against SSRF/local network targets."""

    def test_validate_webhook_url_rejects_non_https(self):
        service = EnhancedNotificationService()
        valid, error = service._validate_webhook_url("http://1.1.1.1/hook", require_https=True)
        assert valid is False
        assert "HTTPS" in str(error)

    def test_validate_webhook_url_rejects_private_or_local_ips(self):
        service = EnhancedNotificationService()
        for url in (
            "https://127.0.0.1/webhook",
            "https://10.0.0.1/webhook",
            "https://192.168.1.10/webhook",
            "https://172.16.0.5/webhook",
        ):
            valid, error = service._validate_webhook_url(url)
            assert valid is False
            assert "non-public IP" in str(error)

    def test_validate_webhook_url_enforces_allowed_host_suffixes(self):
        service = EnhancedNotificationService()
        valid, error = service._validate_webhook_url(
            "https://example.com/webhook",
            allowed_host_suffixes=("slack.com",),
        )
        assert valid is False
        assert "not allowed" in str(error)

    def test_send_webhook_rejects_invalid_url_before_network(self):
        service = EnhancedNotificationService()
        service.config["webhook"]["url"] = "https://127.0.0.1/webhook"
        message = NotificationMessage(
            title="test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(service._send_webhook(message))
        assert result["success"] is False
        assert "Invalid webhook URL" in result["error"]
