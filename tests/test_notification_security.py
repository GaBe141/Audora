"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _email_message() -> NotificationMessage:
    return NotificationMessage(
        title="Subject\nBcc: attacker@example.com",
        content="<script>alert(1)</script>\nNext line",
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookRedirectHardening:
    """Outbound webhook posts must not follow redirects (SSRF bypass)."""

    def test_webhook_posts_disable_redirects(self):
        source = Path(__file__).resolve().parents[1] / "core" / "notification_service.py"
        text = source.read_text(encoding="utf-8")
        assert text.count("allow_redirects=False") >= 3


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and refuse plaintext authentication."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_email_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
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
        captured: dict = {}

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context=None):
                captured["context"] = context

            def login(self, *args, **kwargs):
                captured["login"] = True

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        result = asyncio.run(svc._send_email(_email_message()))
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED

    def test_email_headers_strip_crlf_and_html_is_escaped(self, monkeypatch):
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
        captured: dict = {}

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context=None):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        asyncio.run(svc._send_email(_email_message()))
        msg: MIMEMultipart = captured["msg"]
        assert "\n" not in (msg["Subject"] or "")
        assert "\r" not in (msg["Subject"] or "")
        assert msg.get("Bcc") is None
        html_body = msg.get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body

    def test_attachments_outside_allowed_dirs_are_skipped(self, monkeypatch, tmp_path):
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
        secret = tmp_path / "secret.txt"
        secret.write_text("classified")
        captured: dict = {}

        class DummySMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, *, context=None):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        message = _email_message()
        message.attachments = [str(secret)]
        asyncio.run(svc._send_email(message))
        payload = captured["msg"].get_payload()
        assert all(part.get_content_maintype() != "application" for part in payload)
