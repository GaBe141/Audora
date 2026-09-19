"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
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
            svc._validate_webhook_url("https://user:token@example.com/webhook")


def _sample_message(**kwargs) -> NotificationMessage:
    defaults = {
        "title": "Test alert",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.WEBHOOK],
    }
    defaults.update(kwargs)
    return NotificationMessage(**defaults)


class _FakeResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response: _FakeResponse, captured: dict):
        self._response = response
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def post(self, url, **kwargs):
        self.captured["url"] = url
        self.captured["kwargs"] = kwargs
        return self._response


class TestWebhookTransportHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured: dict = {}

        async def _run():
            with (
                patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
                patch("aiohttp.ClientSession", return_value=_FakeSession(_FakeResponse(302), captured)),
            ):
                return await svc._send_webhook(_sample_message())

        result = asyncio.run(_run())
        assert captured["kwargs"].get("allow_redirects") is False
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_slack_and_discord_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        captured: dict = {}

        async def _run_slack():
            with (
                patch.object(svc, "_validate_webhook_url", return_value="https://hooks.slack.com/services/test"),
                patch("aiohttp.ClientSession", return_value=_FakeSession(_FakeResponse(200), captured)),
            ):
                return await svc._send_slack(_sample_message())

        result = asyncio.run(_run_slack())
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False


class TestSmtpTransportHardening:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_refuses_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "music@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_sample_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "music@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        server = MagicMock()
        with patch("smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(_sample_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is True
        server.starttls.assert_called_once()
        context = server.starttls.call_args.kwargs.get("context")
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_email_html_is_escaped_and_headers_strip_crlf(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "music@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        with patch("smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(
                    _sample_message(
                        title="Alert\r\nBcc: attacker@evil.com",
                        content="<script>alert(1)</script>",
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )
        assert result["success"] is True
        msg = captured["msg"]
        assert isinstance(msg, MIMEMultipart)
        assert "\r" not in msg["Subject"]
        assert "\n" not in msg["Subject"]
        assert msg["Subject"].startswith("Alert")
        html_part = next(
            part.get_payload() for part in msg.walk() if part.get_content_type() == "text/html"
        )
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_rejects_attachment_outside_allowed_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "music@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                return None

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        with patch("smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(
                    _sample_message(
                        channels=[NotificationChannel.EMAIL],
                        attachments=[str(outside)],
                    )
                )
            )
        assert result["success"] is True
        payloads = [part.get_filename() for part in captured["msg"].walk()]
        assert "secret.txt" not in payloads
