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

    @pytest.mark.asyncio
    async def test_custom_webhook_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        response = MagicMock()
        response.status = 302
        response.text = AsyncMock(return_value="redirect")

        post_context = MagicMock()
        post_context.__aenter__.return_value = response
        post_context.__aexit__.return_value = None

        session = MagicMock()
        session.post.return_value = post_context

        session_context = MagicMock()
        session_context.__aenter__.return_value = session
        session_context.__aexit__.return_value = None

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_context),
        ):
            result = await svc._send_webhook(message)

        assert result["success"] is False
        assert result["error"].startswith("HTTP 302")
        session.post.assert_called_once()
        assert session.post.call_args.kwargs["allow_redirects"] is False
