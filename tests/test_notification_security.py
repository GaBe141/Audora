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


def _message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="hello",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )


class _DummyResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self) -> str:
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _DummySession:
    def __init__(self):
        self.post_kwargs: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.post_kwargs = kwargs
        return _DummyResponse()


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


class TestWebhookTransportHardening:
    """Outbound notification HTTP clients must not follow redirects."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        session = _DummySession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_slack(_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        session = _DummySession()
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value=svc.config["discord"]["webhook_url"]
            ),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        session = _DummySession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is True
        assert session.post_kwargs is not None
        assert session.post_kwargs.get("allow_redirects") is False


class TestSmtpTransportHardening:
    """SMTP must use validated TLS and must not send credentials in the clear."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        mock_server = MagicMock()
        ssl_context = ssl.create_default_context()
        with (
            patch("smtplib.SMTP", return_value=mock_server),
            patch("ssl.create_default_context", return_value=ssl_context) as create_ctx,
        ):
            result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        create_ctx.assert_called_once()
        mock_server.starttls.assert_called_once()
        assert mock_server.starttls.call_args.kwargs.get("context") is ssl_context
        assert ssl_context.check_hostname is True
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED
