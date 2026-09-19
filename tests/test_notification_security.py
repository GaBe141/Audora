"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="hello <script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
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
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects."""

    def test_slack_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        response = MagicMock()
        response.status = 302
        response.text = AsyncMock(return_value="redirect")
        session = MagicMock()
        session.post = MagicMock(return_value=AsyncMock())
        session.post.return_value.__aenter__ = AsyncMock(return_value=response)
        session.post.return_value.__aexit__ = AsyncMock(return_value=None)
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/slack"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_slack(_message()))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        response = MagicMock()
        response.status = 204
        session = MagicMock()
        session.post = MagicMock(return_value=AsyncMock())
        session.post.return_value.__aenter__ = AsyncMock(return_value=response)
        session.post.return_value.__aexit__ = AsyncMock(return_value=None)
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/discord"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_discord(_message()))

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        response = MagicMock()
        response.status = 200
        session = MagicMock()
        session.post = MagicMock(return_value=AsyncMock())
        session.post.return_value.__aenter__ = AsyncMock(return_value=response)
        session.post.return_value.__aexit__ = AsyncMock(return_value=None)
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(
                svc, "_validate_webhook_url", return_value="https://hooks.example.com/custom"
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP credentials must only move over verified TLS."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        smtp = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp),
            patch("core.notification_service.ssl.create_default_context") as create_ctx,
        ):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            create_ctx.return_value = ctx
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        create_ctx.assert_called_once()
        smtp.starttls.assert_called_once()
        assert smtp.starttls.call_args.kwargs["context"] is ctx
        smtp.login.assert_called_once()

    def test_email_headers_strip_crlf_and_html_is_escaped(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        smtp = MagicMock()
        captured: dict[str, MIMEMultipart] = {}

        def _send_message(msg):
            captured["msg"] = msg

        smtp.send_message.side_effect = _send_message
        message = NotificationMessage(
            title="Alert\r\nBcc: attacker@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        subject = captured["msg"]["Subject"]
        assert "\r" not in subject
        assert "\n" not in subject
        html_part = captured["msg"].get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
