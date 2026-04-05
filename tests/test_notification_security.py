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
    async def test_webhook_post_disallows_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        svc._validate_webhook_url = lambda url, allow_private=False: url

        class FakeResponse:
            status = 302
            headers = {"Location": "https://127.0.0.1/internal"}

            async def text(self):
                return "redirect"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs):
                self.post_called = False
                self.allow_redirects = None

            def post(self, *args, **kwargs):
                self.post_called = True
                self.allow_redirects = kwargs.get("allow_redirects")
                return FakeResponse()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        captured = {}

        def fake_client_session(*args, **kwargs):
            session = FakeSession()
            captured["session"] = session
            return session

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", fake_client_session)
        try:
            from core.notification_service import NotificationMessage, NotificationPriority

            result = await svc._send_webhook(
                NotificationMessage(
                    title="t",
                    content="c",
                    priority=NotificationPriority.LOW,
                    channels=[],
                )
            )
        finally:
            monkeypatch.undo()

        assert captured["session"].post_called is True
        assert captured["session"].allow_redirects is False
        assert result["success"] is False
        assert "Webhook redirects are not allowed" in result["error"]
