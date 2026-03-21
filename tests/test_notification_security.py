"""Security tests for notification webhook URL validation."""

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


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


class TestNotificationMessageKey:
    """Validate deterministic and strong deduplication key generation."""

    def test_message_key_is_deterministic_sha256(self):
        svc = EnhancedNotificationService()
        msg = NotificationMessage(
            title="Alert",
            content="Important update",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        key1 = svc._generate_message_key(msg)
        key2 = svc._generate_message_key(msg)
        assert key1 == key2
        assert len(key1) == 64
        assert all(ch in "0123456789abcdef" for ch in key1)
