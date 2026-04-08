"""Security tests for notification hardening behaviors."""

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
    """Validate deterministic deduplication key generation."""

    def test_message_key_is_deterministic_for_same_content(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Critical Alert",
            content="Anomaly detected in trend pipeline",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.WEBHOOK, NotificationChannel.SLACK],
            data={"region": "US", "score": 91.2},
        )

        key_1 = svc._generate_message_key(message)
        key_2 = svc._generate_message_key(message)

        assert key_1 == key_2

    def test_message_key_changes_when_content_changes(self):
        svc = EnhancedNotificationService()
        msg_a = NotificationMessage(
            title="Critical Alert",
            content="Anomaly detected in trend pipeline",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.WEBHOOK],
            data={"region": "US"},
        )
        msg_b = NotificationMessage(
            title="Critical Alert",
            content="Anomaly detected in recommendation pipeline",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.WEBHOOK],
            data={"region": "US"},
        )

        assert svc._generate_message_key(msg_a) != svc._generate_message_key(msg_b)


class TestWebhookAuthHeader:
    """Validate safer webhook Authorization header defaults."""

    def test_webhook_authorization_header_absent_when_token_missing(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()
        headers = svc.config["webhook"]["headers"]
        assert "Authorization" not in headers
