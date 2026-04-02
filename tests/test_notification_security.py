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
async def test_webhook_delivery_disables_redirects(monkeypatch):
    """Ensure outbound webhooks do not follow redirects (SSRF hardening)."""
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "https://example.com/webhook"

    class DummyResponse:
        status = 200

        async def text(self):
            return ""

    class DummyRequestContext:
        async def __aenter__(self):
            return DummyResponse()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class DummySession:
        def __init__(self):
            self.post_kwargs = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def post(self, _url, **kwargs):
            self.post_kwargs = kwargs
            return DummyRequestContext()

    dummy_session = DummySession()
    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: dummy_session)
    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,
    )

    from core.notification_service import (
        NotificationChannel,
        NotificationMessage,
        NotificationPriority,
    )

    message = NotificationMessage(
        title="Test",
        content="Test content",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )
    result = await svc.send_notification(message)

    assert result["delivered"] is True
    assert dummy_session.post_kwargs is not None
    assert dummy_session.post_kwargs["allow_redirects"] is False
