"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    _RestrictedWebhookResolver,
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

    def test_rejects_urls_with_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:password@example.com/webhook")

    def test_connection_resolver_rejects_private_rebinding(self, monkeypatch):
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        resolver = _RestrictedWebhookResolver(allow_private=False)

        with pytest.raises(ValueError, match="private or restricted"):
            asyncio.run(resolver.resolve("example.com", 443))

    def test_connection_resolver_allows_private_when_enabled(self, monkeypatch):
        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", port))
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        resolver = _RestrictedWebhookResolver(allow_private=True)

        resolved = asyncio.run(resolver.resolve("example.com", 443))

        assert resolved[0]["host"] == "10.0.0.1"

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        captured_post_kwargs = {}

        class DummyResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class DummySession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, *args, **kwargs):
                captured_post_kwargs.update(kwargs)
                return DummyResponse()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)
        monkeypatch.setattr(svc, "_webhook_connector", lambda **kwargs: None)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)

        msg = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        result = asyncio.run(svc._send_webhook(msg))

        assert result["success"] is True
        assert captured_post_kwargs["allow_redirects"] is False
