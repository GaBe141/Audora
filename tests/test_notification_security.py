"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

import aiohttp
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _MockResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._body


class _MockSession:
    def __init__(self, post_calls: list[dict]):
        self.post_calls = post_calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.post_calls.append({"url": url, **kwargs})
        return _MockResponse(status=302, body="redirect")


class TestWebhookTransportSecurity:
    """Validate outbound notification transport hardening."""

    def test_custom_webhook_disables_and_rejects_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        post_calls = []
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/webhook"),
            patch.object(aiohttp, "ClientSession", return_value=_MockSession(post_calls)),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result == {"success": False, "error": "Webhook redirects are not allowed"}
        assert post_calls[0]["allow_redirects"] is False

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        post_calls = []
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch.object(aiohttp, "ClientSession", return_value=_MockSession(post_calls)),
        ):
            result = asyncio.run(svc._send_slack(message))

        assert result == {"success": False, "error": "Webhook redirects are not allowed"}
        assert post_calls[0]["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        post_calls = []
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/discord"),
            patch.object(aiohttp, "ClientSession", return_value=_MockSession(post_calls)),
        ):
            result = asyncio.run(svc._send_discord(message))

        assert result == {"success": False, "error": "Webhook redirects are not allowed"}
        assert post_calls[0]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_refuses_smtp_auth_without_tls(self):
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
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP") as smtp:
            result = asyncio.run(svc._send_email(message))

        smtp.assert_not_called()
        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
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
        server = MagicMock()
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
