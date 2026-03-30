"""Security tests for notification webhook URL validation and email TLS hardening."""

import asyncio
import ssl
from unittest.mock import patch

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


class _DummySMTP:
    """Test double for smtplib.SMTP that captures TLS behavior."""

    last_instance = None

    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.starttls_context = None
        self.login_args = None
        self.sent_messages = []
        _DummySMTP.last_instance = self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def ehlo(self):
        return 250, b"ok"

    def starttls(self, *, context=None):
        self.starttls_context = context
        return 220, b"ready"

    def login(self, username: str, password: str):
        self.login_args = (username, password)
        return 235, b"ok"

    def send_message(self, msg):
        self.sent_messages.append(msg)
        return {}


class TestEmailTlsSecurity:
    """Validate SMTP TLS settings are secure."""

    def test_email_uses_certificate_validated_tls_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        msg = NotificationMessage(
            title="Security Test",
            content="TLS test",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", _DummySMTP):
            result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        smtp = _DummySMTP.last_instance
        assert smtp is not None
        assert smtp.starttls_context is not None
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.starttls_context.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_email_recipient_normalization_drops_empty_values(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "",
                "password": "",
                "recipients": ["", "  ", "alerts@example.com", " ops@example.com "],
                "use_tls": True,
            }
        )

        msg = NotificationMessage(
            title="Recipient Test",
            content="Recipient normalization",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", _DummySMTP):
            result = asyncio.run(svc._send_email(msg))

        assert result["success"] is True
        assert result["recipients"] == 2
