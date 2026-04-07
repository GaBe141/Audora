"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

import core.notification_service as notification_service
from core.notification_service import (
    EnhancedNotificationService,
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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _DummyResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return ""


class _DummySession:
    def __init__(self, capture: dict) -> None:
        self._capture = capture

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url: str, **kwargs):
        self._capture["url"] = url
        self._capture["kwargs"] = kwargs
        return _DummyResponse(status=200)


class TestWebhookRedirectSecurity:
    """Ensure outbound webhook transports do not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        capture: dict = {}

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr(
            notification_service.aiohttp,
            "ClientSession",
            lambda: _DummySession(capture),
        )
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="t",
                    content="c",
                    priority=NotificationPriority.LOW,
                    channels=[],
                )
            )
        )

        assert result["success"] is True
        assert capture["kwargs"]["allow_redirects"] is False

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        capture: dict = {}

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr(
            notification_service.aiohttp,
            "ClientSession",
            lambda: _DummySession(capture),
        )
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test/test/test"

        result = asyncio.run(
            svc._send_slack(
                NotificationMessage(
                    title="t",
                    content="c",
                    priority=NotificationPriority.LOW,
                    channels=[],
                )
            )
        )

        assert result["success"] is True
        assert capture["kwargs"]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        capture: dict = {}

        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr(
            notification_service.aiohttp,
            "ClientSession",
            lambda: _DummySession(capture),
        )
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test/test"

        result = asyncio.run(
            svc._send_discord(
                NotificationMessage(
                    title="t",
                    content="c",
                    priority=NotificationPriority.LOW,
                    channels=[],
                )
            )
        )

        assert result["success"] is True
        assert capture["kwargs"]["allow_redirects"] is False
