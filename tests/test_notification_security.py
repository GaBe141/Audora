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

    def test_rejects_channel_url_outside_provider_allowlist(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="hostname is not allowed"):
            svc._validate_webhook_url(
                "https://example.com/services/test",
                allowed_hosts={"hooks.slack.com"},
            )

    def test_allows_channel_url_inside_provider_allowlist(self):
        svc = EnhancedNotificationService()
        url = "https://hooks.slack.com/services/test"
        assert svc._validate_webhook_url(url, allowed_hosts={"hooks.slack.com"}) == url


class _FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse()


class TestWebhookDeliverySecurity:
    """Validate outbound webhook delivery uses hardened request settings."""

    def test_custom_webhook_delivery_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        _FakeSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeSession.calls[0][1]["allow_redirects"] is False

    def test_slack_delivery_requires_slack_host(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/webhook"
        _FakeSession.calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is False
        assert _FakeSession.calls == []
