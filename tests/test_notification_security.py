"""Security tests for notification webhook URL validation."""

import hashlib

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
    """Validate deterministic and collision-resistant-ish message keys."""

    def test_uses_stable_sha256_digest(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Security Alert",
            content="Critical event happened in subsystem xyz",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        key = svc._generate_message_key(message)
        raw = f"{message.priority.value}\n{message.title}\n{message.content[:500]}"
        expected_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert key == expected_digest

    def test_same_message_produces_same_key(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Duplicate Check",
            content="Same content should always hash to same key",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.CONSOLE],
        )

        first = svc._generate_message_key(message)
        second = svc._generate_message_key(message)
        assert first == second
