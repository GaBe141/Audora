"""Security tests for notification transport hardening."""

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

    def test_rejects_embedded_credentials(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestEmailTransportSecurity:
    """Validate SMTP credential and STARTTLS hardening."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "pass",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        smtp_instance = MagicMock()
        smtp_instance.__enter__.return_value = smtp_instance
        smtp_instance.__exit__.return_value = None

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = smtp_instance.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
