"""Security tests for notification webhook URL validation."""

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

    def test_rejects_embedded_credentials_in_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _DummyResponse:
    def __init__(self, status=200, text="ok"):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._text


class _DummyClientSession:
    def __init__(self, call_collector):
        self.call_collector = call_collector

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.call_collector.append({"url": url, **kwargs})
        return _DummyResponse()


class TestWebhookRedirectHardening:
    """Ensure outgoing webhook calls do not follow redirects."""

    @pytest.mark.parametrize(
        ("channel", "config_key", "url_key"),
        [
            (NotificationChannel.SLACK, "slack", "webhook_url"),
            (NotificationChannel.DISCORD, "discord", "webhook_url"),
            (NotificationChannel.WEBHOOK, "webhook", "url"),
        ],
    )
    def test_notification_channels_disable_redirects(
        self, monkeypatch, channel, config_key, url_key
    ):
        calls = []
        svc = EnhancedNotificationService()
        svc.config[config_key][url_key] = "https://example.com/webhook"

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: _DummyClientSession(calls),
        )

        msg = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[channel],
        )

        import asyncio

        result = asyncio.run(svc.send_notification(msg))
        assert result["delivered"] is True
        assert calls, "Expected outbound HTTP call"
        assert calls[0]["allow_redirects"] is False
