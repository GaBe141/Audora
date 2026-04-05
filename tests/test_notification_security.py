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


class TestWebhookRedirectHandling:
    """Ensure outbound notifications do not follow redirects."""

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.test/notify"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        msg = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        response = MagicMock(status=200)
        response.text = AsyncMock(return_value="ok")
        post_cm = AsyncMock()
        post_cm.__aenter__.return_value = response
        session = MagicMock()
        session.post.return_value = post_cm
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = session

        with (
            patch("core.notification_service.aiohttp.ClientSession", return_value=session_cm),
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
        ):
            result = asyncio.run(svc.send_notification(msg))

        assert result["delivered"] is True
        session.post.assert_called_once()
        assert session.post.call_args.kwargs.get("allow_redirects") is False
