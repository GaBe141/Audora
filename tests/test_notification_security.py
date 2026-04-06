"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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


class TestEmailTlsHardening:
    """Validate SMTP TLS security controls."""

    def test_rejects_email_send_when_starttls_not_supported(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "recipients": ["alerts@example.com"],
            "use_tls": True,
            "username": "",
            "password": "",
            "from_address": "noreply@example.com",
        }

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def ehlo(self):
                return None

            def has_extn(self, ext):
                return ext.lower() == "noop"

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="test",
                    content="body",
                    priority=NotificationPriority.HIGH,
                    channels=[],
                )
            )
        )
        assert result["success"] is False
        assert "STARTTLS" in result["error"]

    def test_uses_certificate_validated_tls_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "recipients": ["alerts@example.com"],
            "use_tls": True,
            "username": "",
            "password": "",
            "from_address": "noreply@example.com",
        }

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                self.starttls_context = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def ehlo(self):
                return None

            def has_extn(self, ext):
                return ext.lower() == "starttls"

            def starttls(self, context):
                self.starttls_context = context
                return (220, b"ready")

            def send_message(self, _msg):
                return {}

            def login(self, *_args):
                return None

        fake_smtp = FakeSMTP()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *_a, **_k: fake_smtp)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="test",
                    content="body",
                    priority=NotificationPriority.HIGH,
                    channels=[],
                )
            )
        )
        assert result["success"] is True
        assert fake_smtp.starttls_context is not None
        assert fake_smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert fake_smtp.starttls_context.check_hostname is True
        if hasattr(ssl, "TLSVersion"):
            assert fake_smtp.starttls_context.minimum_version >= ssl.TLSVersion.TLSv1_2
