"""Security tests for notification webhook URL validation and hardening logic."""

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


class TestNotificationHardening:
    """Security-focused tests for deterministic keys and auth header behavior."""

    def test_message_key_is_deterministic(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Security test",
            content="Same message body for key generation",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        first = svc._generate_message_key(message)
        second = svc._generate_message_key(message)
        assert first == second

    def test_message_key_changes_with_message_content(self):
        svc = EnhancedNotificationService()
        first = NotificationMessage(
            title="Security test",
            content="First body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        second = NotificationMessage(
            title="Security test",
            content="Second body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        assert svc._generate_message_key(first) != svc._generate_message_key(second)

    def test_webhook_header_omits_authorization_without_token(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()
        assert "Authorization" not in svc.config["webhook"]["headers"]

    def test_webhook_header_includes_authorization_with_token(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_TOKEN", "token123")
        svc = EnhancedNotificationService()
        assert svc.config["webhook"]["headers"]["Authorization"] == "Bearer token123"
