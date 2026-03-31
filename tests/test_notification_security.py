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
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self) -> str:
        return "ok"


class _FakeRequestContext:
    def __init__(self, response: _FakeResponse):
        self._response = response

    async def __aenter__(self) -> _FakeResponse:
        return self._response

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeClientSession:
    def __init__(self, captured: dict[str, Any], response_status: int = 200):
        self._captured = captured
        self._response = _FakeResponse(status=response_status)

    async def __aenter__(self) -> "_FakeClientSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    def post(self, url: str, **kwargs):
        self._captured["url"] = url
        self._captured["kwargs"] = kwargs
        return _FakeRequestContext(self._response)


@pytest.mark.parametrize(
    ("method_name", "config_path", "config_value"),
    [
        ("_send_slack", ("slack", "webhook_url"), "https://hooks.slack.com/services/test"),
        ("_send_discord", ("discord", "webhook_url"), "https://discord.com/api/webhooks/test"),
        ("_send_webhook", ("webhook", "url"), "https://example.com/webhook"),
    ],
)
def test_notification_posts_disable_redirects(
    monkeypatch, method_name: str, config_path: tuple[str, str], config_value: str
):
    """Outbound webhook posts should never follow redirects."""
    captured: dict[str, Any] = {}
    svc = EnhancedNotificationService()

    section, key = config_path
    svc.config[section][key] = config_value
    monkeypatch.setattr(
        "core.notification_service.aiohttp.ClientSession",
        lambda: _FakeClientSession(captured),
    )
    monkeypatch.setattr(
        svc,
        "_validate_webhook_url",
        lambda url, allow_private=False: url,
    )

    message = NotificationMessage(
        title="Security test",
        content="Validate redirect handling",
        priority=NotificationPriority.LOW,
        channels=[],
    )
    sender = getattr(svc, method_name)
    result = asyncio.run(sender(message))

    assert result["success"] is True
    assert captured["kwargs"].get("allow_redirects") is False
