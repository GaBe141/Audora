"""Security tests ensuring webhook notifications do not follow redirects."""

from unittest.mock import MagicMock

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class _DummyResponse:
    def __init__(self, status: int = 200, text_value: str = "ok"):
        self.status = status
        self._text_value = text_value

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._text_value


class _DummySession:
    def __init__(self):
        self.last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *_args, **kwargs):
        self.last_post_kwargs = kwargs
        return _DummyResponse(status=200)


@pytest.mark.parametrize(
    ("channel", "config_key", "url_key"),
    [
        (NotificationChannel.SLACK, "slack", "webhook_url"),
        (NotificationChannel.DISCORD, "discord", "webhook_url"),
        (NotificationChannel.WEBHOOK, "webhook", "url"),
    ],
)
def test_notification_posts_disable_redirects(monkeypatch, channel, config_key, url_key):
    svc = EnhancedNotificationService()
    svc.config[config_key][url_key] = "https://example.com/webhook"
    svc._validate_webhook_url = MagicMock(return_value="https://example.com/webhook")

    dummy_session = _DummySession()
    monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", lambda: dummy_session)

    message = NotificationMessage(
        title="security test",
        content="testing redirect handling",
        priority=NotificationPriority.LOW,
        channels=[channel],
    )

    import asyncio

    result = asyncio.run(svc.send_notification(message))
    assert result["delivered"] is True
    assert dummy_session.last_post_kwargs is not None
    assert dummy_session.last_post_kwargs.get("allow_redirects") is False
