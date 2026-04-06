"""Security tests for notification webhook URL validation."""

import asyncio

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

    def test_notification_posts_disable_redirects(self, monkeypatch):
        """Ensure outbound notification requests never follow redirects."""
        svc = EnhancedNotificationService()

        # Avoid network dependency from DNS lookups in URL validation.
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)

        calls: list[dict[str, object]] = []

        class _FakeResponse:
            def __init__(self, status: int = 200):
                self.status = status

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeClientSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                calls.append({"url": url, "kwargs": kwargs})
                return _FakeResponse(status=200)

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeClientSession)

        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        msg = NotificationMessage(
            title="Security test",
            content="Ensure redirects are disabled.",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        asyncio.run(svc._send_slack(msg))
        asyncio.run(svc._send_discord(msg))
        asyncio.run(svc._send_webhook(msg))

        assert len(calls) == 3
        assert all(call["kwargs"].get("allow_redirects") is False for call in calls)
