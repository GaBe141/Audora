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


class TestNotificationTransportSecurity:
    """Ensure outbound notification requests use hardened transport settings."""

    def test_webhook_post_disables_redirect_following(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        captured: dict[str, object] = {}

        class _FakeResponse:
            status = 200

            async def text(self) -> str:
                return ""

        class _PostContext:
            async def __aenter__(self):
                return _FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class _FakeSession:
            def post(self, _url, **kwargs):
                captured.update(kwargs)
                return _PostContext()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        async def _run():
            from core.notification_service import NotificationMessage, NotificationPriority

            message = NotificationMessage(
                title="Test",
                content="Test",
                priority=NotificationPriority.LOW,
                channels=[],
            )
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr("core.notification_service.aiohttp.ClientSession", lambda: _FakeSession())
                result = await svc._send_webhook(message)
                assert result["success"] is True

        import asyncio

        asyncio.run(_run())
        assert captured["allow_redirects"] is False
