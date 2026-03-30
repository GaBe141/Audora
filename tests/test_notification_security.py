"""Security tests for notification webhook URL validation and transport settings."""

import asyncio

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


class TestWebhookTransportSettings:
    """Validate HTTP client settings for webhook-based channels."""

    def test_disables_redirects_for_webhook_channels(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        svc.config["webhook"]["url"] = "https://example.com/custom"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        # Keep the test deterministic and avoid DNS/network dependencies.
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )

        post_kwargs: list[dict] = []

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, *args, **kwargs):
                post_kwargs.append(kwargs)
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: FakeSession(),
        )

        message = NotificationMessage(
            title="Security Test",
            content="Checking webhook request options.",
            priority=NotificationPriority.HIGH,
            channels=[],
        )

        assert asyncio.run(svc._send_slack(message))["success"] is True
        assert asyncio.run(svc._send_discord(message))["success"] is True
        assert asyncio.run(svc._send_webhook(message))["success"] is True
        assert len(post_kwargs) == 3
        assert all(kwargs.get("allow_redirects") is False for kwargs in post_kwargs)
