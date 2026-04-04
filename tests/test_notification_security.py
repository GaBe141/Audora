"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import patch

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


class TestWebhookRedirectHandling:
    """Validate redirect-related SSRF protections for outbound notifications."""

    def test_custom_webhook_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        captured: dict[str, object] = {}

        class _DummyResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return "ok"

        class _DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _DummyResponse()

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        with patch("core.notification_service.aiohttp.ClientSession", return_value=_DummySession()):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert captured.get("allow_redirects") is False

    def test_slack_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"

        captured: dict[str, object] = {}

        class _DummyResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return "ok"

        class _DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _DummyResponse()

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        with patch("core.notification_service.aiohttp.ClientSession", return_value=_DummySession()):
            result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert captured.get("allow_redirects") is False

    def test_discord_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        captured: dict[str, object] = {}

        class _DummyResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return "ok"

        class _DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _DummyResponse()

        message = NotificationMessage(
            title="test",
            content="test content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        with patch("core.notification_service.aiohttp.ClientSession", return_value=_DummySession()):
            result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert captured.get("allow_redirects") is False
