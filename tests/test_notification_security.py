"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


def _email_message() -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="<script>alert(1)</script>\nline2",
        priority=NotificationPriority.LOW,
        channels=[],
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

    def test_rejects_cgnat_addresses(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.1.1/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        assert svc._is_restricted_ip("::ffff:10.1.2.3") is True

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookRedirectHardening:
    """Outbound webhook POSTs must not follow redirects."""

    def test_slack_disables_redirects(self):
        captured: dict = {}

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return FakeResponse()

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        msg = _email_message()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_slack(msg))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_webhook_rejects_redirect_status(self):
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

            def post(self, url, **kwargs):
                return FakeResponse()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        msg = _email_message()
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(msg))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS before authentication."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_email_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_email_message()))
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED
        assert captured["login"] == ("user", "pass")
        assert isinstance(captured["msg"], MIMEMultipart)
        html_part = captured["msg"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
        assert "alert(1)" in html_part

    def test_rejects_attachments_outside_project_root(self, tmp_path):
        outside = tmp_path / "secret.txt"
        outside.write_text("should-not-attach")
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(outside)) is None
