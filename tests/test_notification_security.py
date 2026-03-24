"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.notification_service import EnhancedNotificationService
from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority


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
    """Ensure webhook channel requests do not follow redirects."""

    def test_webhook_post_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 10

        message = NotificationMessage(
            title="Security test",
            content="Ensure redirects are disabled",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.WEBHOOK],
        )

        with patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]), patch(
            "core.notification_service.aiohttp.ClientSession"
        ) as mock_session_cls:
            mock_response = AsyncMock()
            mock_response.status = 200

            mock_post_context = AsyncMock()
            mock_post_context.__aenter__.return_value = mock_response

            mock_session = MagicMock()
            mock_session.post.return_value = mock_post_context
            mock_session_context = AsyncMock()
            mock_session_context.__aenter__.return_value = mock_session
            mock_session_cls.return_value = mock_session_context

            result = asyncio.run(svc._send_webhook(message))

            assert result["success"] is True
            assert mock_session.post.call_args.kwargs["allow_redirects"] is False
