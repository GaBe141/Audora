"""Security tests for notification webhook URL validation."""

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


class TestEmailSecurity:
    """Validate secure email transport and HTML escaping."""

    @pytest.mark.asyncio
    async def test_email_uses_verified_tls_context_and_escapes_html(self):
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
        smtp = MagicMock()

        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp),
            patch(
                "core.notification_service.ssl.create_default_context",
                wraps=ssl.create_default_context,
            ) as create_default_context,
        ):
            result = await svc._send_email(
                NotificationMessage(
                    title="Security alert",
                    content="<script>alert('xss')</script>\nline",
                    priority=NotificationPriority.HIGH,
                    channels=[NotificationChannel.EMAIL],
                )
            )

        assert result["success"] is True
        create_default_context.assert_called_once_with()
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        sent_message = smtp.send_message.call_args.args[0]
        html_part = sent_message.get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
