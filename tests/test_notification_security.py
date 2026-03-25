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


class _MockResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._body


class _MockSession:
    def __init__(self, recorder: dict[str, object], *args, **kwargs):
        self._recorder = recorder
        self._recorder["session_kwargs"] = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self._recorder["post_args"] = args
        self._recorder["post_kwargs"] = kwargs
        return _MockResponse(status=200)


class TestWebhookDeliverySecurity:
    def test_custom_webhook_disables_redirects_and_strips_empty_bearer(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ",
        }

        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda url, allow_private=False: url
        )
        recorder: dict[str, object] = {}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: _MockSession(recorder, *args, **kwargs),
        )

        message = NotificationMessage(
            title="test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert recorder["post_kwargs"]["allow_redirects"] is False
        headers = recorder["post_kwargs"]["headers"]
        assert "Authorization" not in headers
