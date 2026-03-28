"""Security tests for notification webhook URL validation."""

from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import EnhancedNotificationService
from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority


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


class TestEmailTransportSecurity:
    """Validate secure SMTP behavior for outbound email."""

    @pytest.mark.asyncio
    async def test_requires_tls_by_default(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "sender@example.com",
            "recipients": ["recipient@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Test",
            content="secure mail",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        smtp_mock = MagicMock()
        smtp_mock.starttls = MagicMock()
        smtp_mock.login = MagicMock()
        smtp_mock.send_message = MagicMock()
        smtp_mock.quit = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_mock):
            result = await svc._send_email(message)

        assert result["success"] is True
        smtp_mock.starttls.assert_called_once()

    @pytest.mark.asyncio
    async def test_rejects_plaintext_smtp_when_opted_out(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "sender@example.com",
            "recipients": ["recipient@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Test",
            content="insecure mail",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)
        assert result["success"] is False
        assert "TLS is required" in result["error"]
