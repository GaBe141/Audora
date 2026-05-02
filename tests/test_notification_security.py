"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import EnhancedNotificationService, StaticWebhookResolver


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

    def test_rejects_redirect_to_private_target(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/webhook", allow_private=False)


class TestSecureWebhookConnector:
    """Validate connection-time network restrictions for outbound webhooks."""

    def test_connector_rejects_unexpected_redirect_hosts(self):
        async def run_check():
            resolver = StaticWebhookResolver(
                "example.com",
                [
                    {
                        "hostname": "example.com",
                        "host": "93.184.216.34",
                        "port": 443,
                        "family": 0,
                        "proto": 0,
                        "flags": 0,
                    }
                ],
            )

            try:
                with pytest.raises(OSError, match="Unexpected webhook redirect host"):
                    await resolver.resolve("127.0.0.1", 443)
            finally:
                await resolver.close()

        asyncio.run(run_check())
