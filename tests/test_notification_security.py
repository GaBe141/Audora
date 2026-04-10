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

    def test_rejects_embedded_credentials_in_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


def test_webhook_post_disables_redirects(monkeypatch):
    """Ensure webhook delivery explicitly disables redirect following."""
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
    svc.config["webhook"]["timeout"] = 5

    captured_kwargs: dict[str, object] = {}

    class FakeResponse:
        status = 200

        async def text(self):
            return "ok"

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        def post(self, _url, **kwargs):
            captured_kwargs.update(kwargs)
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: FakeSession())
    # Keep URL validation behavior out-of-scope for this specific redirect test.
    monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

    message = NotificationMessage(
        title="redirect-test",
        content="test",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.WEBHOOK],
    )

    result = asyncio.run(svc._send_webhook(message))
    assert result["success"] is True
    assert captured_kwargs.get("allow_redirects") is False
