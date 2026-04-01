"""Security tests for notification webhook URL validation."""

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


class TestWebhookRedirectProtection:
    """Validate that outbound webhooks never follow redirects."""

    @pytest.mark.parametrize(
        ("channel", "channel_config", "expected_url"),
        [
            (
                NotificationChannel.SLACK,
                {"slack": {"webhook_url": "https://example.com/slack"}},
                "https://example.com/slack",
            ),
            (
                NotificationChannel.DISCORD,
                {"discord": {"webhook_url": "https://example.com/discord"}},
                "https://example.com/discord",
            ),
            (
                NotificationChannel.WEBHOOK,
                {"webhook": {"url": "https://example.com/custom", "headers": {}, "timeout": 5}},
                "https://example.com/custom",
            ),
        ],
    )
    def test_outbound_posts_disable_redirects(self, channel, channel_config, expected_url):
        svc = EnhancedNotificationService()
        svc.config.update(channel_config)

        message = NotificationMessage(
            title="test",
            content="test payload",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

        response = AsyncMock()
        response.status = 200
        response.text = AsyncMock(return_value="ok")

        post_cm = AsyncMock()
        post_cm.__aenter__.return_value = response
        post_cm.__aexit__.return_value = False

        session_instance = MagicMock()
        session_instance.post.return_value = post_cm

        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = session_instance
        session_cm.__aexit__.return_value = False

        with (
            patch("core.notification_service.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
        ):
            result = __import__("asyncio").run(svc.send_notification(message))

        assert result["delivered"] is True
        session_instance.post.assert_called_once()
        _, kwargs = session_instance.post.call_args
        assert kwargs["allow_redirects"] is False
        assert session_instance.post.call_args.args[0] == expected_url
