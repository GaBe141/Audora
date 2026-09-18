"""Security tests for notification webhook URL validation and transport hardening."""

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


def _public_dns(*_args, **_kwargs):
    return [(0, 0, 0, 0, ("1.1.1.1", 443))]


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

    def test_sanitize_header_strips_crlf(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Subject\r\nBcc: attacker@example.com") == "SubjectBcc: attacker@example.com"


class TestWebhookTransportHardening:
    """Outbound webhook posts must not follow redirects."""

    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="Test",
            content="Hello",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured: dict = {}

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured.update(kwargs)
                return FakeResponse()

        with (
            patch("socket.getaddrinfo", side_effect=_public_dns),
            patch("aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(self._message(NotificationChannel.WEBHOOK)))

        assert captured.get("allow_redirects") is False
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_slack_and_discord_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        captured = []

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def post(self, url, **kwargs):
                captured.append(kwargs.get("allow_redirects"))
                return FakeResponse()

        with (
            patch("socket.getaddrinfo", side_effect=_public_dns),
            patch("aiohttp.ClientSession", return_value=FakeSession()),
        ):
            asyncio.run(svc._send_slack(self._message(NotificationChannel.SLACK)))
            asyncio.run(svc._send_discord(self._message(NotificationChannel.DISCORD)))

        assert captured == [False, False]


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext auth."""

    def test_refuses_plaintext_smtp_auth(self):
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
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
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
        message = NotificationMessage(
            title="Alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with patch("smtplib.SMTP", return_value=smtp) as smtp_cls:
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        smtp_cls.assert_called_once()
        assert smtp.starttls.called
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_body_escapes_content(self):
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
        message = NotificationMessage(
            title="Alert",
            content="<b>owned</b>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        smtp = MagicMock()
        with patch("smtplib.SMTP", return_value=smtp):
            asyncio.run(svc._send_email(message))

        sent_msg = smtp.send_message.call_args[0][0]
        html_part = sent_msg.get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode("utf-8")
        assert "<b>owned</b>" not in html_body
        assert "&lt;b&gt;owned&lt;/b&gt;" in html_body
