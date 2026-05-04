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


class _FakePostContext:
    def __init__(self, captured_kwargs):
        self.status = 200
        self._captured_kwargs = captured_kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def text(self):
        return ""


class _FakeClientSession:
    captured_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    def post(self, _url, **kwargs):
        type(self).captured_kwargs = kwargs
        return _FakePostContext(kwargs)


@pytest.mark.asyncio
async def test_custom_webhook_disables_redirects(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
    )
    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)

    message = NotificationMessage(
        title="Test",
        content="Body",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.WEBHOOK],
    )

    result = await svc._send_webhook(message)

    assert result["success"] is True
    assert _FakeClientSession.captured_kwargs["allow_redirects"] is False
