"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
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


class _MockResponseContext:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return "response body"


class _MockClientSession:
    def __init__(self, *args, **kwargs):
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return _MockResponseContext(status=200)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="Test notification",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.WEBHOOK],
    )


class TestWebhookTransportSecurity:
    """Validate outbound webhook transport hardening."""

    def test_slack_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/webhook"
        session = _MockClientSession()

        with (
            patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_slack(_message()))

        assert result["success"] is True
        assert session.post_calls[0][1]["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        session = _MockClientSession()

        with (
            patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_discord(_message()))

        assert result["success"] is True
        assert session.post_calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://webhook.example/notify"
        session = _MockClientSession()

        with (
            patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert session.post_calls[0][1]["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP credential transport hardening."""

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "password",
            }
        )

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        server = MagicMock()

        with patch("smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
