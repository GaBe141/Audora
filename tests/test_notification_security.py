"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    _ResolvedAddress,
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

    def test_rejects_hostname_when_any_resolved_address_is_private(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("10.0.0.5", 443),
                ),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/webhook")


class _FakeWebhookResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def text(self):
        return ""


class _FakeWebhookSession:
    post_kwargs: list[dict] = []

    def __init__(self, *_args, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def post(self, _url, **kwargs):
        self.post_kwargs.append(kwargs)
        return _FakeWebhookResponse()


class TestWebhookDeliverySecurity:
    """Validate outbound webhook client hardening."""

    def _pin_dns(self, svc, monkeypatch):
        def fake_validate(url, *, allow_private=False):
            return (
                url,
                "example.com",
                (_ResolvedAddress("93.184.216.34", socket.AF_INET, socket.IPPROTO_TCP, 0),),
            )

        monkeypatch.setattr(svc, "_validate_webhook_target", fake_validate)

    def test_slack_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        self._pin_dns(svc, monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeWebhookSession)
        _FakeWebhookSession.post_kwargs = []

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakeWebhookSession.post_kwargs[0]["allow_redirects"] is False

    def test_discord_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"
        self._pin_dns(svc, monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeWebhookSession)
        _FakeWebhookSession.post_kwargs = []

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.DISCORD],
        )

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert _FakeWebhookSession.post_kwargs[0]["allow_redirects"] is False

    def test_custom_webhook_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        self._pin_dns(svc, monkeypatch)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeWebhookSession)
        _FakeWebhookSession.post_kwargs = []

        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeWebhookSession.post_kwargs[0]["allow_redirects"] is False
