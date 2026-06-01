"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

import core.notification_service as notification_service
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

    def test_webhook_posts_do_not_follow_redirects(self, monkeypatch):
        captured_kwargs = {}

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return "ok"

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr(notification_service.aiohttp, "ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        status, body = asyncio.run(
            svc._post_json_webhook("https://example.com/webhook", {"ok": True})
        )

        assert status == 200
        assert body == "ok"
        assert captured_kwargs["allow_redirects"] is False
