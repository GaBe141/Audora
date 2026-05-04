"""Security tests for notification webhook URL validation."""

import asyncio
import socket

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

    def test_pins_validated_dns_answers(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*args, **kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        target = svc._validated_webhook_target("https://example.com/webhook")

        assert target.url == "https://example.com/webhook"
        assert "93.184.216.34" in target._connector._addresses

    def test_webhook_sends_with_redirects_disabled(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        class FakeResponse:
            status = 302

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return "redirect"

        class FakeSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, *args, **kwargs):
                assert kwargs["allow_redirects"] is False
                return FakeResponse()

        class FakeTarget:
            async def __aenter__(self):
                return "https://example.com/webhook", None

            async def __aexit__(self, exc_type, exc, tb):
                return None

        monkeypatch.setattr(
            svc,
            "_validated_webhook_target",
            lambda url, allow_private=False: FakeTarget(),
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="Security test",
                    content="Test content",
                    priority=NotificationPriority.HIGH,
                    channels=[],
                )
            )
        )

        assert result["success"] is False
        assert result["error"] == "HTTP 302: redirect"
