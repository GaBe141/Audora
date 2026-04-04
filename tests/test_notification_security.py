"""Security tests for notification webhook URL validation."""

import asyncio
from unittest.mock import patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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

    def test_webhook_sender_disables_redirect_following(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

        class DummyRequestContext:
            async def __aenter__(self):
                return DummyResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            def __init__(self):
                self.post_kwargs = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                self.post_kwargs = kwargs
                return DummyRequestContext()

        dummy_session = DummySession()

        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        with patch("core.notification_service.aiohttp.ClientSession", return_value=dummy_session):
            result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert dummy_session.post_kwargs is not None
        assert dummy_session.post_kwargs.get("allow_redirects") is False
