"""Security tests for notification webhook URL validation and key handling."""

import pytest
from yarl import URL

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class _DummyResponse:
    """Minimal response shape for redirect validation helper tests."""

    def __init__(self, current_url: str, location: str | None) -> None:
        self.url = URL(current_url)
        self.headers = {}
        if location is not None:
            self.headers["Location"] = URL(location)


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

    def test_redirect_requires_location_header(self):
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url  # type: ignore[method-assign]
        response = _DummyResponse("https://hooks.example.com/base", None)
        with pytest.raises(ValueError, match="Location"):
            svc._resolve_safe_redirect_url(response, "https://hooks.example.com/base", allow_private=False)

    def test_redirect_blocks_cross_host_targets(self):
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url  # type: ignore[method-assign]
        response = _DummyResponse("https://hooks.example.com/base", "https://attacker.example.net/collect")
        with pytest.raises(ValueError, match="across hosts"):
            svc._resolve_safe_redirect_url(response, "https://hooks.example.com/base", allow_private=False)

    def test_redirect_allows_same_host_targets(self):
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, allow_private=False: url  # type: ignore[method-assign]
        response = _DummyResponse("https://hooks.example.com/base", "/next")
        resolved = svc._resolve_safe_redirect_url(
            response, "https://hooks.example.com/base", allow_private=False
        )
        assert resolved == "https://hooks.example.com/next"


class TestNotificationMessageKey:
    """Ensure notification deduplication keys are deterministic."""

    def test_message_key_is_stable_for_same_message(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Title",
            content="Body content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        assert svc._generate_message_key(message) == svc._generate_message_key(message)

    def test_message_key_changes_when_priority_changes(self):
        svc = EnhancedNotificationService()
        low = NotificationMessage(
            title="Title",
            content="Body content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.CONSOLE],
        )
        high = NotificationMessage(
            title="Title",
            content="Body content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        assert svc._generate_message_key(low) != svc._generate_message_key(high)
