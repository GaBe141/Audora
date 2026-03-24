"""Security tests for notification webhook URL validation."""

from unittest.mock import MagicMock, patch

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


class TestNotificationEmailSecurity:
    """Validate SMTP security hardening and header sanitization."""

    def test_sanitize_email_header_rejects_newlines(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="newline"):
            svc._sanitize_email_header("safe@example.com\nInjected: true", "From address")

    @pytest.mark.asyncio
    async def test_send_email_uses_tls_with_verified_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["from_address"] = "alerts@example.com"
        svc.config["email"]["recipients"] = ["user@example.com"]
        svc.config["email"]["use_tls"] = True
        svc.config["email"]["username"] = ""
        svc.config["email"]["password"] = ""

        message = NotificationMessage(
            title="Security Test",
            content="Testing SMTP TLS context",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        mock_server = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=mock_server),
            patch("core.notification_service.ssl.create_default_context", return_value="tls_ctx") as ctx_mock,
        ):
            result = await svc._send_email(message)

        assert result["success"] is True
        ctx_mock.assert_called_once()
        mock_server.starttls.assert_called_once_with(context="tls_ctx")
        mock_server.send_message.assert_called_once()
