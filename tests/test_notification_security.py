"""Security tests for notification webhook URL validation."""

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


class TestNotificationTransportHardening:
    """Validate secure transport and deterministic deduplication behavior."""

    def test_message_key_is_stable_and_sha256(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Security test",
            content="Deterministic key generation should be stable.",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
            data={"track_id": "abc123"},
        )

        key1 = svc._generate_message_key(message)
        key2 = svc._generate_message_key(message)

        assert key1 == key2
        assert len(key1) == 64
        assert all(ch in "0123456789abcdef" for ch in key1)

    @patch("core.notification_service.ssl.create_default_context")
    @patch("core.notification_service.smtplib.SMTP")
    @pytest.mark.asyncio
    async def test_email_starttls_uses_ssl_context(self, smtp_cls, default_context):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["security@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )

        smtp_server = MagicMock()
        smtp_cls.return_value.__enter__.return_value = smtp_server
        tls_context = MagicMock()
        default_context.return_value = tls_context

        message = NotificationMessage(
            title="TLS test",
            content="Ensure TLS context is used.",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is True
        default_context.assert_called_once()
        smtp_server.starttls.assert_called_once_with(context=tls_context)
