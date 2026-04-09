"""Security tests for notification webhook URL validation."""

import asyncio

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


def test_send_webhook_disables_redirects(monkeypatch):
    """Webhook sender must not follow redirects after URL validation."""
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
    svc.config["webhook"]["timeout"] = 10

    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,  # noqa: ARG005
    )

    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200

        async def text(self):
            return "ok"

    class FakePostContext:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001, ARG002
            return False

    class FakeClientSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):  # noqa: ANN001, ARG002
            return False

        def post(self, *args, **kwargs):  # noqa: ANN002, ANN003
            captured["args"] = args
            captured["kwargs"] = kwargs
            return FakePostContext()

    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeClientSession)

    message = NotificationMessage(
        title="Test",
        content="Test content",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )
    result = asyncio.run(svc._send_webhook(message))
    assert result["success"] is True
    assert captured["kwargs"]["allow_redirects"] is False
