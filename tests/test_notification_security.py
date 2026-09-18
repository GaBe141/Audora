"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**overrides) -> NotificationMessage:
    defaults = {
        "title": "Alert",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.EMAIL],
    }
    defaults.update(overrides)
    return NotificationMessage(**defaults)


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
    """Outbound webhook clients must not follow redirects."""

    def test_slack_disables_redirects_and_rejects_3xx(self):
        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, json=None, **kwargs):
                captured["kwargs"] = kwargs
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]),
            patch("aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_slack(_message(channels=[NotificationChannel.SLACK])))

        assert captured["kwargs"].get("allow_redirects") is False
        assert result["success"] is False
        assert "Redirects" in result["error"]

    def test_custom_webhook_disables_redirects(self):
        captured: dict = {}
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"

        class FakeResponse:
            status = 301

            async def text(self):
                return "moved"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, json=None, headers=None, timeout=None, **kwargs):
                captured["kwargs"] = kwargs
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(_message(channels=[NotificationChannel.WEBHOOK])))

        assert captured["kwargs"].get("allow_redirects") is False
        assert result["success"] is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and never send credentials in the clear."""

    def test_refuses_smtp_auth_without_tls(self):
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
        result = asyncio.run(svc._send_email(_message(content="<script>alert(1)</script>")))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        captured: dict = {}
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

        with patch("smtplib.SMTP", FakeSMTP):
            result = asyncio.run(
                svc._send_email(_message(title="Track\nBcc: evil@example.com", content="<b>hi</b>"))
            )

        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        msg = captured["msg"]
        assert isinstance(msg, MIMEMultipart)
        assert "\n" not in (msg["Subject"] or "")
        assert "\r" not in (msg["Subject"] or "")
        html_part = msg.get_payload()[1].get_payload()
        assert "<b>hi</b>" not in html_part
        assert "&lt;b&gt;hi&lt;/b&gt;" in html_part

    def test_rejects_attachment_outside_allowed_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("classified")
        resolved = svc._resolve_attachment_path(str(outside))
        assert resolved is None
