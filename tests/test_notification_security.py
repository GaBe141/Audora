"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


class _FakeResponse:
    """Minimal async context manager representing an HTTP response."""

    def __init__(self, status: int, headers: dict[str, str] | None = None, body: str = "") -> None:
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self) -> str:
        return self._body


class _FakeSession:
    """Minimal async aiohttp session stub for webhook tests."""

    def __init__(self, response: _FakeResponse, request_capture: dict[str, object]) -> None:
        self._response = response
        self._request_capture = request_capture

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):  # noqa: ANN001
        self._request_capture["url"] = url
        self._request_capture["kwargs"] = kwargs
        return self._response


class _FakeClientSessionFactory:
    """Factory emulating aiohttp.ClientSession constructor."""

    def __init__(self, response: _FakeResponse, request_capture: dict[str, object]) -> None:
        self._response = response
        self._request_capture = request_capture

    def __call__(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return _FakeSession(self._response, self._request_capture)


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

    def test_custom_webhook_blocks_redirect_responses(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        request_capture: dict[str, object] = {}
        fake_response = _FakeResponse(
            status=302, headers={"Location": "https://127.0.0.1/internal"}, body="redirect"
        )

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            _FakeClientSessionFactory(fake_response, request_capture),
        )

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is False
        assert "Redirects are not allowed for webhooks" in result["error"]

    def test_custom_webhook_drops_blank_authorization_header(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        svc.config["webhook"]["headers"] = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ",
            "X-Test": "ok",
        }
        request_capture: dict[str, object] = {}
        fake_response = _FakeResponse(status=200)

        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            _FakeClientSessionFactory(fake_response, request_capture),
        )

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        headers = request_capture["kwargs"]["headers"]
        assert "Authorization" not in headers
        assert headers["X-Test"] == "ok"
