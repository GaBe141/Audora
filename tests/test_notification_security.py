"""Security tests for notification service hardening."""

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


class TestNotificationDeduplication:
    """Validate deterministic and collision-resistant dedupe keys."""

    def test_message_key_is_stable_across_equivalent_payloads(self):
        svc = EnhancedNotificationService()
        msg_a = NotificationMessage(
            title="Security Alert",
            content="Potential issue detected",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
            data={"metric": 123, "severity": "high"},
        )
        # Same logical payload but with channels in different order should dedupe.
        msg_b = NotificationMessage(
            title="Security Alert",
            content="Potential issue detected",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
            data={"severity": "high", "metric": 123},
        )

        key_a = svc._generate_message_key(msg_a)
        key_b = svc._generate_message_key(msg_b)
        assert key_a == key_b

    def test_message_key_changes_when_message_changes(self):
        svc = EnhancedNotificationService()
        base_message = NotificationMessage(
            title="Alert",
            content="A",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.SLACK],
        )
        changed_message = NotificationMessage(
            title="Alert",
            content="B",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.SLACK],
        )
        assert svc._generate_message_key(base_message) != svc._generate_message_key(
            changed_message
        )
