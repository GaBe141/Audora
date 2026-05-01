"""Security tests for notification webhook URL validation."""

from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import EnhancedNotificationService


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
    """Validate bounded, verified SMTP transport."""

    def test_email_uses_timeout_and_verified_starttls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "timeout": 12,
            }
        )

        message = MagicMock()
        message.title = "Security alert"
        message.content = "body"
        message.priority = MagicMock()
        message.priority.value = "high"
        message.attachments = None
        message.template_vars = None

        smtp_instance = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance) as smtp, patch(
            "core.notification_service.ssl.create_default_context", return_value="tls-context"
        ):
            result = __import__("asyncio").run(svc._send_email(message))

        assert result["success"] is True
        smtp.assert_called_once_with("smtp.example.com", 587, timeout=12)
        smtp_instance.starttls.assert_called_once_with(context="tls-context")
        smtp_instance.quit.assert_called_once()
