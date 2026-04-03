"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


class _FakeResponse:
    """Minimal async response object for aiohttp mocking."""

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
    """Minimal async client session that records POST kwargs."""

    def __init__(self, calls: list[dict[str, object]]):
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url: str, **kwargs):
        self._calls.append({"url": url, "kwargs": kwargs})
        return _FakeResponse(status=200)


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


class TestWebhookRedirectHardening:
    """Ensure outbound webhooks do not follow redirects (SSRF hardening)."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="security test",
            content="test",
            priority=NotificationPriority.LOW,
            channels=[],
        )

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom-webhook"

        calls: list[dict[str, object]] = []
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(calls),
        )

        result = asyncio.run(svc._send_webhook(self._message()))
        assert result["success"] is True
        assert calls, "Expected webhook POST call"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack-webhook"

        calls: list[dict[str, object]] = []
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(calls),
        )

        result = asyncio.run(svc._send_slack(self._message()))
        assert result["success"] is True
        assert calls, "Expected Slack POST call"
        assert calls[0]["kwargs"]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord-webhook"

        calls: list[dict[str, object]] = []
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeClientSession(calls),
        )

        result = asyncio.run(svc._send_discord(self._message()))
        assert result["success"] is True
        assert calls, "Expected Discord POST call"
        assert calls[0]["kwargs"]["allow_redirects"] is False
