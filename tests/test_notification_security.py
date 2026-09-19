"""Security tests for notification webhook URL validation."""

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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@8.8.8.8/webhook")


class _DummyResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self):
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _DummySession:
    def __init__(self):
        self.post_kwargs = None

    def post(self, url, **kwargs):
        self.post_kwargs = kwargs
        return _DummyResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class TestWebhookTransportHardening:
    """Outbound webhook sends must not follow redirects."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        dummy = _DummySession()
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=dummy),
        ):
            result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert dummy.post_kwargs["allow_redirects"] is False

    def test_slack_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        dummy = _DummySession()
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=dummy),
        ):
            result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert dummy.post_kwargs["allow_redirects"] is False

    def test_discord_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        dummy = _DummySession()
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/discord"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=dummy),
        ):
            result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert dummy.post_kwargs["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def _email_message(self):
        return NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

    def test_smtp_auth_requires_tls(self):
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
        result = asyncio.run(svc._send_email(self._email_message()))
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
        server = MagicMock()
        ssl_context = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=server),
            patch(
                "core.notification_service.ssl.create_default_context",
                return_value=ssl_context,
            ) as mock_ctx,
        ):
            result = asyncio.run(svc._send_email(self._email_message()))
        assert result["success"] is True
        mock_ctx.assert_called_once()
        server.starttls.assert_called_once()
        assert server.starttls.call_args.kwargs["context"] is ssl_context

    def test_html_body_escapes_user_content(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        server = MagicMock()
        message = NotificationMessage(
            title="Alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        sent = server.send_message.call_args.args[0]
        html_part = sent.get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
