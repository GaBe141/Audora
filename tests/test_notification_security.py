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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_url_fragments(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="fragments"):
            svc._validate_webhook_url("https://example.com/webhook#fragment")


class TestNotificationMessageKey:
    """Validate deterministic and safe deduplication keys."""

    def test_message_key_is_deterministic_across_equivalent_payloads(self):
        svc = EnhancedNotificationService()
        msg_one = NotificationMessage(
            title="Test Title",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
            data={"b": 2, "a": 1},
        )
        msg_two = NotificationMessage(
            title="Test Title",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
            data={"a": 1, "b": 2},
        )
        key_one = svc._generate_message_key(msg_one)
        key_two = svc._generate_message_key(msg_two)
        assert key_one == key_two
        assert len(key_one) == 64
