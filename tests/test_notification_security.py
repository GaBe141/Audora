"""Security tests for notification transport hardening."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

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
    """Async context manager that captures aiohttp post kwargs."""

    calls: list[dict] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.response = AsyncMock()
        self.response.status = 200
        self.response.text = AsyncMock(return_value="")

    async def __aenter__(self):
        self.calls.append(self.kwargs)
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeClientSession:
    """Async context manager with a synchronous post method like aiohttp."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        return _FakePostContext(url=url, **kwargs)


class TestNotificationTransports:
    """Validate protections on outbound notification transports."""

    def test_slack_post_does_not_follow_redirects(self):
        _FakePostContext.calls = []
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        message = NotificationMessage(
            title="Alert",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", _FakeClientSession),
        ):
            result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakePostContext.calls[0]["allow_redirects"] is False

    def test_discord_post_does_not_follow_redirects(self):
        _FakePostContext.calls = []
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        message = NotificationMessage(
            title="Alert",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", _FakeClientSession),
        ):
            result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert _FakePostContext.calls[0]["allow_redirects"] is False

    def test_custom_webhook_post_does_not_follow_redirects(self):
        _FakePostContext.calls = []
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Alert",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", _FakeClientSession),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakePostContext.calls[0]["allow_redirects"] is False

    def test_email_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Alert",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_email_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Alert",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch("core.notification_service.ssl.create_default_context") as create_context,
        ):
            create_context.return_value = MagicMock()
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        create_context.assert_called_once_with()
        server.starttls.assert_called_once_with(context=create_context.return_value)
