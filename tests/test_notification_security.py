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


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS before authentication."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
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
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED


class TestEmailContentHardening:
    """Email headers and HTML bodies must not accept attacker-controlled markup."""

    def test_strips_crlf_from_headers(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_email_header("Subject\r\nBcc: evil@example.com") == "SubjectBcc: evil@example.com"

    def test_rejects_attachments_outside_allowlist(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.chdir(tmp_path)
        secret = tmp_path / "secret.env"
        secret.write_text("password=1")
        assert svc._is_allowed_attachment_path(secret) is False
        allowed = tmp_path / "data" / "report.csv"
        allowed.parent.mkdir()
        allowed.write_text("a,b")
        assert svc._is_allowed_attachment_path(allowed) is True


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects."""

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeSession:
            def __init__(self):
                self.post_kwargs = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, url, **kwargs):
                self.post_kwargs = kwargs
                return FakeResponse()

        session = FakeSession()
        message = NotificationMessage(
            title="Alert",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_webhook(message))
        assert session.post_kwargs["allow_redirects"] is False
        assert result["success"] is False
        assert "Redirect" in result["error"]
