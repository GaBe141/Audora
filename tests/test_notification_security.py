"""Security tests for notification webhook URL validation."""

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


class TestNotificationTransportSecurity:
    """Validate secure transport behavior for notification channels."""

    @pytest.mark.parametrize("method_name", ["_send_slack", "_send_discord", "_send_webhook"])
    def test_webhook_channels_disable_redirects(self, method_name):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/webhook"
        svc.config["discord"]["webhook_url"] = "https://discord.example/webhook"
        svc.config["webhook"]["url"] = "https://webhook.example/notify"
        message = NotificationMessage(
            title="Title",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        class MockResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return ""

        class MockSession:
            def __init__(self):
                self.post = MagicMock(return_value=MockResponse())

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        session = MockSession()

        with (
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
            patch.object(
                svc,
                "_validate_webhook_url",
                side_effect=lambda url, allow_private=False: url,
            ),
        ):
            asyncio.run(getattr(svc, method_name)(message))

        assert session.post.call_args.kwargs["allow_redirects"] is False

    def test_email_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Title",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )
        server = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=server):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_email_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Title",
            content="Content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=MagicMock()) as smtp:
            result = asyncio.run(svc._send_email(message))

        smtp.assert_called_once()
        smtp.return_value.login.assert_not_called()
        assert result["success"] is False
        assert "without TLS" in result["error"]
