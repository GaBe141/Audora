"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock

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
        channels=[NotificationChannel.WEBHOOK],
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


class TestWebhookTransportHardening:
    """Outbound webhook posts must not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        captured: dict = {}

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, *args, **kwargs):
                captured["kwargs"] = kwargs
                return DummyResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False

    def test_custom_webhook_rejects_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class DummyResponse:
            status = 302

            async def text(self):
                return "moved"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, *args, **kwargs):
                return DummyResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()

    def test_slack_and_discord_disable_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        captured = []

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, *args, **kwargs):
                captured.append(kwargs)
                return DummyResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        asyncio.run(svc._send_slack(_message()))
        asyncio.run(svc._send_discord(_message()))
        assert len(captured) == 2
        assert all(kwargs.get("allow_redirects") is False for kwargs in captured)


class TestSmtpTransportHardening:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "unencrypted" in result["error"].lower()

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        captured: dict = {}

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED

    def test_email_html_body_is_escaped_and_headers_sanitized(self, monkeypatch):
        captured: dict = {}

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                return None

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com\nBcc: evil@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Alert\nX-Injected: yes",
            content="hello <script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        msg = captured["msg"]
        assert isinstance(msg, MIMEMultipart)
        assert "\n" not in msg["Subject"]
        assert "\n" not in msg["From"]
        html_body = msg.get_payload()[1].get_payload()
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body

    def test_rejects_attachment_outside_allowed_directories(self, tmp_path, monkeypatch):
        captured = MagicMock()

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                return None

            def send_message(self, msg):
                captured.msg = msg

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
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
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
            attachments=[str(outside)],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        payloads = captured.msg.get_payload()
        assert all(part.get_content_type() != "application/octet-stream" for part in payloads)
