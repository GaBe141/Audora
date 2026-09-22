"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import EnhancedNotificationService, _PinnedWebhookResolver


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

    def test_blocks_loopback_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/webhook", allow_private=True)

    def test_rejects_credentials_and_obfuscated_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")
        with pytest.raises(ValueError, match="obfuscated"):
            svc._validate_webhook_url("https://0177.0.0.1/webhook")
        with pytest.raises(ValueError, match="blocked hostname"):
            svc._validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_pinned_resolver_refuses_unvalidated_host(self):
        resolver = _PinnedWebhookResolver("example.com", ["1.2.3.4"])

        async def _resolve():
            return await resolver.resolve("169.254.169.254", 443)

        with pytest.raises(OSError, match="not validated"):
            asyncio.run(_resolve())
