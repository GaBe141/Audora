"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from unittest.mock import MagicMock, patch

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
        content="<script>alert(1)</script>\nline 2",
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_cgnat_ip_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        fake_info = [(0, 0, 0, "", ("::ffff:127.0.0.1", 443))]
        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=fake_info),
            pytest.raises(ValueError, match="private or restricted"),
        ):
            svc._validate_webhook_url("https://evil.example/webhook")

    def test_cgnat_ip_is_restricted(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        assert svc._is_restricted_ip("8.8.8.8") is False

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookRedirects:
    """Outbound webhooks must not follow redirects to internal hosts."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
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
            def post(self, url, **kwargs):
                captured["kwargs"] = kwargs
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        msg = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class FakeResponse:
            status = 302

            async def text(self):
                return "moved"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            def post(self, url, **kwargs):
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        msg = NotificationMessage(
            title="Test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is False
        assert "Redirects" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS before authenticating."""

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
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "plaintext SMTP" in result["error"]

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
        fake_server = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=fake_server):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        context = fake_server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_email_escapes_content(self):
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
        fake_server = MagicMock()
        sent: dict = {}

        def capture(msg):
            sent["msg"] = msg

        fake_server.send_message.side_effect = capture

        with patch("core.notification_service.smtplib.SMTP", return_value=fake_server):
            asyncio.run(svc._send_email(_message()))

        html_part = None
        assert isinstance(sent["msg"], MIMEMultipart)
        for part in sent["msg"].walk():
            if part.get_content_type() == "text/html":
                html_part = part.get_payload(decode=True).decode()
        assert html_part is not None
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part


class TestAttachmentPathConfinement:
    """Email attachments must stay inside the project tree."""

    def test_rejects_path_traversal(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("nope")
        assert svc._resolve_attachment_path(str(secret)) is None

    def test_allows_project_file(self):
        svc = EnhancedNotificationService()
        project_file = Path(__file__).resolve().parents[1] / "README.md"
        resolved = svc._resolve_attachment_path("README.md")
        assert resolved == project_file.resolve()
