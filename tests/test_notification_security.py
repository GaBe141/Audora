"""Security tests for notification webhook URL validation."""

import ssl
from unittest.mock import AsyncMock, MagicMock, patch

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
    """Verify outbound transports keep security controls at send time."""

    @pytest.mark.parametrize(
        ("channel", "method_name", "config_key", "success_status"),
        [
            (NotificationChannel.SLACK, "_send_slack", "slack", 200),
            (NotificationChannel.DISCORD, "_send_discord", "discord", 204),
            (NotificationChannel.WEBHOOK, "_send_webhook", "webhook", 200),
        ],
    )
    @pytest.mark.asyncio
    async def test_webhook_channels_disable_redirects(
        self, channel, method_name, config_key, success_status
    ):
        svc = EnhancedNotificationService()
        if config_key == "webhook":
            svc.config[config_key]["url"] = "https://example.com/webhook"
        else:
            svc.config[config_key]["webhook_url"] = "https://example.com/webhook"

        message = NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[channel],
        )

        response = AsyncMock()
        response.status = success_status
        response.text = AsyncMock(return_value="")

        post_context = MagicMock()
        post_context.__aenter__ = AsyncMock(return_value=response)
        post_context.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.post.return_value = post_context
        session_context = MagicMock()
        session_context.__aenter__ = AsyncMock(return_value=session)
        session_context.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_context),
        ):
            result = await getattr(svc, method_name)(message)

        assert result["success"] is True
        assert session.post.call_args.kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_email_rejects_plaintext_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "user",
                "password": "secret",
                "recipients": ["user@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP"):
            result = await svc._send_email(message)

        assert result["success"] is False
        assert "Refusing to authenticate" in result["error"]
        smtp.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_email_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "username": "",
                "password": "",
                "recipients": ["user@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="test",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        tls_context = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(tls_context, ssl.SSLContext)
        assert tls_context.check_hostname is True
        assert tls_context.verify_mode == ssl.CERT_REQUIRED
