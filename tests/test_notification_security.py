"""Security tests for notification webhook URL validation and key generation."""

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


class TestMessageKeyGeneration:
    """Validate message deduplication key behavior."""

    def test_message_key_is_deterministic_and_hex(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Critical Alert",
            content="A" * 150,  # key generation only uses first 100 chars
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.CONSOLE],
        )

        first = svc._generate_message_key(message)
        second = svc._generate_message_key(message)
        assert first == second

        digest, priority = first.split(":", 1)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
        assert priority == NotificationPriority.CRITICAL.value
