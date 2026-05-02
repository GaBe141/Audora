"""Security tests for notification transport hardening."""

import asyncio
from unittest.mock import MagicMock, patch

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class _MockResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "redirect"


class _MockSession:
    last_post_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.__class__.last_post_kwargs = kwargs
        return _MockResponse(status=302)


class TestWebhookTransportHardening:
    """Validate outbound requests cannot follow redirect-based SSRF chains."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/webhook"),
            patch("core.notification_service.aiohttp.ClientSession", _MockSession),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is False
        assert _MockSession.last_post_kwargs is not None
        assert _MockSession.last_post_kwargs["allow_redirects"] is False

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", _MockSession),
        ):
            result = asyncio.run(svc._send_slack(message))

        assert result["success"] is False
        assert _MockSession.last_post_kwargs is not None
        assert _MockSession.last_post_kwargs["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/discord"),
            patch("core.notification_service.aiohttp.ClientSession", _MockSession),
        ):
            result = asyncio.run(svc._send_discord(message))

        assert result["success"] is False
        assert _MockSession.last_post_kwargs is not None
        assert _MockSession.last_post_kwargs["allow_redirects"] is False


class TestSmtpTransportHardening:
    """Validate SMTP credentials are only sent over verified TLS."""

    def test_smtp_auth_requires_tls(self):
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
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

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
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        mock_server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=mock_server):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = mock_server.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode.name == "CERT_REQUIRED"
