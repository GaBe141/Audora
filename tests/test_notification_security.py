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
    async def test_webhook_post_disables_redirect_following(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"

        captured: dict[str, object] = {}

        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured.update(kwargs)
                return DummyResponse()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: DummySession(),
        )
        monkeypatch.setattr(
            "core.notification_service.EnhancedNotificationService._validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )

        from core.notification_service import NotificationMessage, NotificationPriority

        result = await svc._send_webhook(
            NotificationMessage(
                title="test",
                content="body",
                priority=NotificationPriority.LOW,
                channels=[],
            )
        )

        assert result["success"] is True
        assert captured.get("allow_redirects") is False
