"""Security-focused tests for notification service behavior."""

import os

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestNotificationSecurityHardening:
    """Validate security hardening changes."""

    def test_message_key_is_stable_and_deterministic(self):
        svc = EnhancedNotificationService()
        msg = NotificationMessage(
            title="Critical Alert",
            content="Something happened",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL],
        )

        key_one = svc._generate_message_key(msg)
        key_two = svc._generate_message_key(msg)

        assert key_one == key_two
        assert key_one.endswith(f":{NotificationPriority.CRITICAL.value}")
        digest = key_one.split(":")[0]
        assert len(digest) == 64
        assert all(ch in "0123456789abcdef" for ch in digest)

    def test_webhook_authorization_header_only_set_when_token_present(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()
        headers = svc.config["webhook"]["headers"]
        assert "Authorization" not in headers

        monkeypatch.setenv("WEBHOOK_TOKEN", "test-token")
        svc_with_token = EnhancedNotificationService()
        headers_with_token = svc_with_token.config["webhook"]["headers"]
        assert headers_with_token["Authorization"] == "Bearer test-token"
