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

    def test_post_json_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect blocked"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeClientSession:
            def __init__(self, *args, **kwargs):
                captured["timeout"] = kwargs.get("timeout")

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["payload"] = kwargs.get("json")
                captured["headers"] = kwargs.get("headers")
                captured["allow_redirects"] = kwargs.get("allow_redirects")
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeClientSession)

        status_code, response_text = asyncio.run(
            svc._post_json_no_redirects(
                "https://example.com/webhook",
                {"hello": "world"},
                headers={"Content-Type": "application/json"},
                timeout_seconds=15,
            )
        )

        assert status_code == 302
        assert response_text == "redirect blocked"
        assert captured["allow_redirects"] is False
        assert captured["url"] == "https://example.com/webhook"
        assert captured["payload"] == {"hello": "world"}
