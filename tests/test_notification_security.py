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


class _DummyResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._body


class _DummySession:
    last_post_kwargs: dict = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.__class__.last_post_kwargs = kwargs
        return _DummyResponse(status=200)


class TestWebhookRedirectProtection:
    """Ensure webhook-style channels do not follow redirects."""

    def test_custom_webhook_disables_redirect_following(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _DummySession)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(msg))
        assert result["success"] is True
        assert _DummySession.last_post_kwargs.get("allow_redirects") is False

    def test_slack_disables_redirect_following(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _DummySession)

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/B/X"
        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(msg))
        assert result["success"] is True
        assert _DummySession.last_post_kwargs.get("allow_redirects") is False

    def test_discord_disables_redirect_following(self, monkeypatch):
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _DummySession)

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/abc"
        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(msg))
        assert result["success"] is True
        assert _DummySession.last_post_kwargs.get("allow_redirects") is False
