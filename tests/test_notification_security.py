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

    def test_rejects_private_ip_even_when_env_flag_is_set(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")


class _MockResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _MockSession:
    post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return _MockResponse()


class TestWebhookTransportSecurity:
    """Validate outbound webhook transport hardening."""

    def _message(self, channel: NotificationChannel) -> NotificationMessage:
        return NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.MEDIUM,
            channels=[channel],
        )

    @pytest.mark.asyncio
    async def test_slack_post_disables_redirects(self, monkeypatch):
        _MockSession.post_calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _MockSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = await svc._send_slack(self._message(NotificationChannel.SLACK))

        assert result["success"] is True
        assert _MockSession.post_calls[0][1]["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_discord_post_disables_redirects(self, monkeypatch):
        _MockSession.post_calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _MockSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = await svc._send_discord(self._message(NotificationChannel.DISCORD))

        assert result["success"] is True
        assert _MockSession.post_calls[0][1]["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_custom_webhook_post_disables_redirects(self, monkeypatch):
        _MockSession.post_calls = []
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _MockSession)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        result = await svc._send_webhook(self._message(NotificationChannel.WEBHOOK))

        assert result["success"] is True
        assert _MockSession.post_calls[0][1]["allow_redirects"] is False
