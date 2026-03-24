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

    def test_webhook_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        def fake_validate(url, *, allow_private=False):
            return url

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

        class FakePostContext:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        captured: dict[str, object] = {}

        class FakeClientSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["allow_redirects"] = kwargs.get("allow_redirects")
                return FakePostContext()

        monkeypatch.setattr(svc, "_validate_webhook_url", fake_validate)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeClientSession)

        result = asyncio.run(
            svc._send_webhook(
                message=type(
                    "Msg",
                    (),
                    {
                        "title": "t",
                        "content": "c",
                        "priority": type("P", (), {"value": "low"})(),
                        "data": {},
                        "template_vars": None,
                    },
                )()
            )
        )

        assert result["success"] is True
        assert captured["allow_redirects"] is False
