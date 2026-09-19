"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.header import decode_header
from pathlib import Path
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**overrides) -> NotificationMessage:
    payload = {
        "title": "Test notice",
        "content": "hello world",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.WEBHOOK],
    }
    payload.update(overrides)
    return NotificationMessage(**payload)


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
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured: dict = {}

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class FakeResponse:
            status = 302

            async def text(self) -> str:
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

            def post(self, url, **kwargs):
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()

    def test_slack_and_discord_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/hook"
        svc.config["discord"]["webhook_url"] = "https://discord.example/hook"
        captured: list[bool | None] = []

        class FakeResponse:
            status = 204

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

            def post(self, url, **kwargs):
                captured.append(kwargs.get("allow_redirects"))
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **kw: url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            asyncio.run(svc._send_slack(_message()))
            asyncio.run(svc._send_discord(_message()))

        assert captured == [False, False]


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not auth in the clear."""

    def _email_config(self, **overrides) -> dict:
        config = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        config.update(overrides)
        return config

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED

    def test_refuses_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config(use_tls=False)
        result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_html_body_is_escaped(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self, context=None):
                pass

            def login(self, username, password):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(
                    _message(
                        channels=[NotificationChannel.EMAIL],
                        content="<script>alert(1)</script>",
                    )
                )
            )

        assert result["success"] is True
        html_part = captured["msg"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_email_headers_strip_crlf(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self, context=None):
                pass

            def login(self, username, password):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(
                    _message(
                        channels=[NotificationChannel.EMAIL],
                        title="Hello\r\nBcc: attacker@evil.com",
                    )
                )
            )

        assert result["success"] is True
        raw_subject = captured["msg"]["Subject"]
        decoded = "".join(
            part.decode(charset or "utf-8") if isinstance(part, bytes) else part
            for part, charset in decode_header(raw_subject)
        )
        assert "\r" not in decoded
        assert "\n" not in decoded
        assert captured["msg"]["Bcc"] is None

    def test_rejects_attachment_outside_allowed_directories(self, tmp_path: Path):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        captured: dict = {}
        secret = tmp_path / "secret.txt"
        secret.write_text("should-not-attach")

        class FakeSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self, context=None):
                pass

            def login(self, username, password):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(
                    _message(
                        channels=[NotificationChannel.EMAIL],
                        attachments=[str(secret)],
                    )
                )
            )

        assert result["success"] is True
        payloads = captured["msg"].get_payload()
        assert all(part.get_content_disposition() != "attachment" for part in payloads)
