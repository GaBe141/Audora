"""Security tests for notification URL validation and outbound request hardening."""

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
    def __init__(self, status: int = 200, text_value: str = "ok"):
        self.status = status
        self._text_value = text_value

    async def text(self) -> str:
        return self._text_value


class _MockPostContext:
    def __init__(self, response: _MockResponse):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _MockSession:
    def __init__(self, calls: list[dict]):
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self._calls.append({"url": url, "kwargs": kwargs})
        return _MockPostContext(_MockResponse())


class TestOutboundWebhookSecurity:
    """Ensure outbound webhook requests keep redirect protections enabled."""

    def test_send_webhook_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert calls, "Expected outbound webhook request"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_send_slack_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        result = asyncio.run(svc._send_slack(msg))

        assert result["success"] is True
        assert calls, "Expected outbound Slack request"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_send_discord_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        calls: list[dict] = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: _MockSession(calls))

        msg = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        result = asyncio.run(svc._send_discord(msg))

        assert result["success"] is True
        assert calls, "Expected outbound Discord request"
        assert calls[0]["kwargs"]["allow_redirects"] is False
