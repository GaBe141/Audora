"""Security tests for notification webhook URL validation."""

import asyncio
import pytest
from unittest.mock import patch

from core.notification_service import EnhancedNotificationService
from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority


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


class _DummyResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _DummySession:
    def __init__(self):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _DummyResponse(status=200)


def test_custom_webhook_disables_redirects():
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"
    msg = NotificationMessage(
        title="test",
        content="body",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )

    session = _DummySession()
    with patch("core.notification_service.aiohttp.ClientSession", return_value=session):
        result = asyncio.run(svc._send_webhook(msg))

    assert result["success"] is True
    assert session.calls, "Expected outbound webhook call"
    _url, kwargs = session.calls[0]
    assert kwargs.get("allow_redirects") is False
