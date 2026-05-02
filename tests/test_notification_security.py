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

    def test_rejects_slack_webhook_on_non_slack_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="hostname is not allowed"):
            svc._validate_webhook_url(
                "https://example.com/services/T000/B000/token",
                allowed_hosts=svc._slack_webhook_hosts(),
            )

    def test_rejects_discord_webhook_on_non_discord_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="hostname is not allowed"):
            svc._validate_webhook_url(
                "https://example.com/api/webhooks/id/token",
                allowed_hosts=svc._discord_webhook_hosts(),
            )

    def test_empty_bearer_header_is_removed(self):
        svc = EnhancedNotificationService()
        assert svc._redact_secret_headers(
            {"Content-Type": "application/json", "Authorization": "Bearer "}
        ) == {"Content-Type": "application/json"}

    def test_custom_webhook_disables_redirects_and_pins_dns(self, monkeypatch):
        captured = {}

        class FakeResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        class FakeSession:
            def __init__(self, *args, **kwargs):
                captured["connector"] = kwargs.get("connector")

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["post_kwargs"] = kwargs
                return FakeResponse()

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(
            svc,
            "_resolve_webhook_target",
            lambda *args, **kwargs: type(
                "Target",
                (),
                {
                    "url": "https://example.com/hook",
                    "hostname": "example.com",
                    "port": 443,
                    "endpoints": [{"ip": "93.184.216.34", "family": 2, "proto": 6}],
                },
            )(),
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="Test",
                    content="Body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.WEBHOOK],
                )
            )
        )

        assert result["success"] is True
        assert captured["connector"] is not None
        assert captured["post_kwargs"]["allow_redirects"] is False
