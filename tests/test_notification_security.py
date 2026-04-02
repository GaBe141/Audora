"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import EnhancedNotificationService


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

    def test_webhook_sender_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 5

        captured_kwargs: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert captured_kwargs.get("allow_redirects") is False

    def test_slack_sender_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T000/B000/XXX"

        captured_kwargs: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self) -> str:
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        from core.notification_service import NotificationMessage, NotificationPriority

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert captured_kwargs.get("allow_redirects") is False

    def test_discord_sender_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/2"

        captured_kwargs: dict[str, object] = {}

        class FakeResponse:
            status = 204

            async def text(self) -> str:
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        from core.notification_service import NotificationMessage, NotificationPriority

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert captured_kwargs.get("allow_redirects") is False
