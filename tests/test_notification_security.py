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


class _FakeResponse:
    """Minimal aiohttp response mock for async context usage."""

    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._body


class _FakeClientSession:
    """Minimal aiohttp session mock that records POST kwargs."""

    def __init__(self):
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse()


class TestWebhookRedirectHardening:
    """Ensure webhook notifications do not follow redirects."""

    def _make_message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="security-test",
            content="security-test",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        holder: dict[str, _FakeClientSession] = {}

        def _session_factory():
            holder["session"] = _FakeClientSession()
            return holder["session"]

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _session_factory)

        result = asyncio.run(svc._send_slack(self._make_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert holder["session"].calls
        assert holder["session"].calls[-1]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        holder: dict[str, _FakeClientSession] = {}

        def _session_factory():
            holder["session"] = _FakeClientSession()
            return holder["session"]

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _session_factory)

        result = asyncio.run(svc._send_discord(self._make_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert holder["session"].calls
        assert holder["session"].calls[-1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc._validate_webhook_url = lambda url, allow_private=False: url

        holder: dict[str, _FakeClientSession] = {}

        def _session_factory():
            holder["session"] = _FakeClientSession()
            return holder["session"]

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _session_factory)

        result = asyncio.run(svc._send_webhook(self._make_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is True
        assert holder["session"].calls
        assert holder["session"].calls[-1]["allow_redirects"] is False
