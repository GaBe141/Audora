"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from pathlib import Path
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _email_message() -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="<script>alert(1)</script>\nnext line",
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

    def test_rejects_cgnat_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/webhook")


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects to private hosts."""

    def test_channel_posts_disable_redirects(self):
        source = Path("core/notification_service.py").read_text(encoding="utf-8")
        assert source.count("allow_redirects=False") >= 3

    def test_rejects_redirect_status_codes(self):
        svc = EnhancedNotificationService()
        assert svc._reject_redirect_status(302) is not None
        assert svc._reject_redirect_status(200) is None


class TestSmtpTransportSecurity:
    """SMTP must not authenticate over plaintext and must validate TLS."""

    def test_rejects_auth_without_tls(self):
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
        result = asyncio.run(svc._send_email(_email_message()))
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
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, *args, **kwargs):
                captured["login"] = True

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_email_message()))

        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        html_payload = captured["msg"].as_string()
        assert "<script>alert(1)</script>" not in html_payload
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_payload


class TestAttachmentConfinement:
    """Email attachments must stay inside the project root."""

    def test_rejects_attachment_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        assert svc._resolve_safe_attachment(str(outside)) is None

    def test_accepts_project_root_file(self, tmp_path):
        svc = EnhancedNotificationService()
        with patch("core.notification_service._PROJECT_ROOT", tmp_path):
            inside = tmp_path / "report.txt"
            inside.write_text("ok", encoding="utf-8")
            assert svc._resolve_safe_attachment(str(inside)) == inside.resolve()
