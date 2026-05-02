"""Security tests for notification webhook URL validation and transports."""

import ssl
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

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

    def test_rejects_webhook_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportSecurity:
    """Validate network transport hardening for outbound notifications."""

    @pytest.mark.asyncio
    async def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        message = NotificationMessage(
            title="Test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        response = MagicMock()
        response.status = 200
        response.__aenter__.return_value = response
        response.__aexit__.return_value = None

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/webhook"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = await svc._send_webhook(message)

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        message = NotificationMessage(
            title="Test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        response = MagicMock()
        response.status = 200
        response.__aenter__.return_value = response
        response.__aexit__.return_value = None

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/slack"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = await svc._send_slack(message)

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        message = NotificationMessage(
            title="Test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        response = MagicMock()
        response.status = 204
        response.__aenter__.return_value = response
        response.__aexit__.return_value = None

        session = MagicMock()
        session.post.return_value = response
        session.__aenter__.return_value = session
        session.__aexit__.return_value = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value="https://example.com/discord"),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = await svc._send_discord(message)

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP credential and TLS handling."""

    @pytest.mark.asyncio
    async def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "use_tls": False,
                "username": "user",
                "password": "secret",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    @pytest.mark.asyncio
    async def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        message = NotificationMessage(
            title="Test",
            content="payload",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
