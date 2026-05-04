"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
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

    def test_pins_validated_webhook_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*args, **kwargs):
            return [
                (
                    2,
                    1,
                    6,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)

        destination = svc._validate_webhook_destination("https://example.com/webhook")

        assert destination.url == "https://example.com/webhook"
        assert destination.addresses == (("93.184.216.34", 2),)

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        captured_post_kwargs = {}

        def fake_getaddrinfo(*args, **kwargs):
            return [
                (
                    2,
                    1,
                    6,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)

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
                captured_post_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        message = NotificationMessage(
            title="Security test",
            content="Should not follow redirects",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert captured_post_kwargs["allow_redirects"] is False
        assert result["success"] is False
        assert result["error"].startswith("HTTP 302")
