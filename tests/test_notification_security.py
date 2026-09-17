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
        title="Test",
        content="Body <script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[channel],
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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_cgnat_and_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransportHardening:
    """Outbound webhook clients must not follow redirects."""

    def test_slack_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        result = asyncio.run(self._post_with_status(svc._send_slack, 302, "Location"))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()

    def test_discord_passes_allow_redirects_false(self):
        captured: dict[str, object] = {}

        class _Response:
            status = 204

            async def text(self) -> str:
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return _Response()

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1"
        discord_url = svc.config["discord"]["webhook_url"]
        with (
            patch.object(svc, "_validate_webhook_url", return_value=discord_url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()),
        ):
            result = asyncio.run(svc._send_discord(_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_passes_allow_redirects_false(self):
        captured: dict[str, object] = {}

        class _Response:
            status = 200

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return _Response()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hooks/audora"
        webhook_url = svc.config["webhook"]["url"]
        with (
            patch.object(svc, "_validate_webhook_url", return_value=webhook_url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()),
        ):
            result = asyncio.run(svc._send_webhook(_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    async def _post_with_status(self, sender, status: int, body: str):
        class _Response:
            def __init__(self):
                self.status = status

            async def text(self) -> str:
                return body

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                return _Response()

        svc_self = sender.__self__
        with (
            patch.object(
                svc_self, "_validate_webhook_url", return_value="https://hooks.example.com/slack"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_Session()),
        ):
            return await sender(_message(NotificationChannel.SLACK))


class TestSmtpTransportHardening:
    """SMTP must not send credentials over plaintext and must validate TLS."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
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
        server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=server) as smtp_cls:
            result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        smtp_cls.assert_called_once()
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_email_escapes_content(self):
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
        captured: dict[str, object] = {}

        def _send_message(msg):
            captured["html"] = msg.get_payload()[1].get_payload(decode=True).decode("utf-8")

        server = MagicMock()
        server.send_message.side_effect = _send_message
        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        html_body = str(captured["html"])
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body
