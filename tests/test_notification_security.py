"""Security tests for notification webhook URL validation."""

import asyncio
from typing import Any

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


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


class _FakeResponse:
    """Minimal async response mock for aiohttp post context manager."""

    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._body


class _FakeSession:
    """Minimal async session mock that records outbound post kwargs."""

    def __init__(self):
        self.post_calls: list[dict[str, Any]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, _url: str, **kwargs):
        self.post_calls.append(kwargs)
        return _FakeResponse()


def _sample_message() -> NotificationMessage:
    return NotificationMessage(
        title="test",
        content="test message",
        priority=NotificationPriority.LOW,
        channels=[],
    )


class TestWebhookRedirectHandling:
    """Regression tests for redirect-based SSRF bypasses."""

    def test_custom_webhook_disables_redirect_following(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        # Keep this test focused on transport behavior, not DNS/network.
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,  # noqa: ARG005
        )
        fake_session = _FakeSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: fake_session,
        )

        result = asyncio.run(svc._send_webhook(_sample_message()))

        assert result["success"] is True
        assert fake_session.post_calls, "Expected outbound webhook POST call"
        assert fake_session.post_calls[0]["allow_redirects"] is False

    def test_slack_webhook_disables_redirect_following(self, monkeypatch: pytest.MonkeyPatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,  # noqa: ARG005
        )
        fake_session = _FakeSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: fake_session,
        )

        result = asyncio.run(svc._send_slack(_sample_message()))

        assert result["success"] is True
        assert fake_session.post_calls, "Expected outbound Slack POST call"
        assert fake_session.post_calls[0]["allow_redirects"] is False
