"""Security tests for notification transport hardening."""

import asyncio
import html
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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportHardening:
    """Validate notification transports do not weaken TLS or redirect protections."""

    def test_email_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["to@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Alert",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_email_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "pass",
                "recipients": ["to@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Alert",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_email_html_body_escapes_message_content(self):
        svc = EnhancedNotificationService()
        content = '<script>alert("x")</script>\nSecond line'
        html_body = svc._build_email_html(content)

        assert html.escape(content).replace("\n", "<br>") in html_body
        assert "<script>" not in html_body

    def test_webhook_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Alert",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        class FakeResponse:
            status = 200

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class FakeSession:
            last_kwargs = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            def post(self, _url, **kwargs):
                FakeSession.last_kwargs = kwargs
                return FakeResponse()

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/webhook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=FakeSession()),
        ):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert FakeSession.last_kwargs["allow_redirects"] is False
