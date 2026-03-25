"""Security tests for notification webhook URL validation."""

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

    @pytest.mark.asyncio
    async def test_send_webhook_disables_redirects_and_uses_timeout(self, monkeypatch):
        """Webhook delivery should not follow redirects to avoid SSRF bypasses."""
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc.config["webhook"]["timeout"] = 7

        captured: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self):
                return "ok"

        class FakeRequestContext:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, *args, **kwargs):
                captured["args"] = args
                captured["kwargs"] = kwargs
                return FakeRequestContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        monkeypatch.setattr(
            svc, "_validate_webhook_url", lambda value, allow_private=False: value
        )

        result = await svc._send_webhook(
            message=type(
                "Message",
                (),
                {
                    "title": "title",
                    "content": "content",
                    "priority": type("Priority", (), {"value": "low"})(),
                    "data": {},
                    "template_vars": None,
                },
            )()
        )

        assert result["success"] is True
        kwargs = captured["kwargs"]
        assert kwargs["allow_redirects"] is False
        timeout = kwargs["timeout"]
        assert timeout.total == 7
