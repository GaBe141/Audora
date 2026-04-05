"""Security tests for notification webhook URL validation."""

import asyncio
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


class TestNotificationTransportHardening:
    """Validate network-level hardening for notification transports."""

    def test_webhook_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        response = MagicMock()
        response.status = 200
        response.text = AsyncMock(return_value="ok")

        post_cm = MagicMock()
        post_cm.__aenter__ = AsyncMock(return_value=response)
        post_cm.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.post = MagicMock(return_value=post_cm)

        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 443))]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(
                svc._send_webhook(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.WEBHOOK],
                    )
                )
            )

        assert result["success"] is True
        _, kwargs = session.post.call_args
        assert kwargs["allow_redirects"] is False

    def test_email_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )

        smtp_client = MagicMock()
        mock_context = MagicMock()
        with (
            patch("core.notification_service.smtplib.SMTP", return_value=smtp_client),
            patch("core.notification_service.ssl.create_default_context", return_value=mock_context),
        ):
            result = asyncio.run(
                svc._send_email(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )

        assert result["success"] is True
        smtp_client.starttls.assert_called_once_with(context=mock_context)

    def test_slack_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        response = MagicMock()
        response.status = 200
        response.text = AsyncMock(return_value="ok")

        post_cm = MagicMock()
        post_cm.__aenter__ = AsyncMock(return_value=response)
        post_cm.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.post = MagicMock(return_value=post_cm)

        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 443))]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(
                svc._send_slack(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.SLACK],
                    )
                )
            )

        assert result["success"] is True
        _, kwargs = session.post.call_args
        assert kwargs["allow_redirects"] is False

    def test_discord_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        response = MagicMock()
        response.status = 204
        response.text = AsyncMock(return_value="ok")

        post_cm = MagicMock()
        post_cm.__aenter__ = AsyncMock(return_value=response)
        post_cm.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.post = MagicMock(return_value=post_cm)

        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 443))]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = asyncio.run(
                svc._send_discord(
                    NotificationMessage(
                        title="t",
                        content="c",
                        priority=NotificationPriority.LOW,
                        channels=[NotificationChannel.DISCORD],
                    )
                )
            )

        assert result["success"] is True
        _, kwargs = session.post.call_args
        assert kwargs["allow_redirects"] is False
