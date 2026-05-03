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
class TestWebhookDeliverySecurity:
    """Validate safe HTTP client options for outbound webhooks."""

    async def test_custom_webhook_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="Security test",
            content="Do not follow redirects",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        response = AsyncMock()
        response.__aenter__.return_value.status = 302
        response.__aenter__.return_value.text = AsyncMock(return_value="redirect")

        session = AsyncMock()
        session.__aenter__.return_value.post = MagicMock(return_value=response)

        with (
            patch.object(
                svc,
                "_validate_webhook_url",
                return_value="https://example.com/webhook",
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = await svc._send_webhook(message)

        session.__aenter__.return_value.post.assert_called_once()
        assert session.__aenter__.return_value.post.call_args.kwargs["allow_redirects"] is False
        assert result["success"] is False

    async def test_slack_webhook_does_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        message = NotificationMessage(
            title="Security test",
            content="Do not follow redirects",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        response = AsyncMock()
        response.__aenter__.return_value.status = 302
        response.__aenter__.return_value.text = AsyncMock(return_value="redirect")

        session = AsyncMock()
        session.__aenter__.return_value.post = MagicMock(return_value=response)

        with (
            patch.object(
                svc,
                "_validate_webhook_url",
                return_value="https://hooks.slack.com/services/test",
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = await svc._send_slack(message)

        session.__aenter__.return_value.post.assert_called_once()
        assert session.__aenter__.return_value.post.call_args.kwargs["allow_redirects"] is False
        assert result["success"] is False
