"""Security tests for notification webhook URL validation."""

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
        target = svc._validate_webhook_url(url, allow_private=True)
        assert target.url == url
        assert target.resolved_ips == ("10.0.0.1",)

    def test_rejects_urls_with_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    @pytest.mark.asyncio
    async def test_pins_resolution_to_validated_host(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_url("https://10.0.0.1/webhook", allow_private=True)
        resolver = StaticWebhookResolver(target)

        resolved = await resolver.resolve("10.0.0.1", 443)
        assert resolved[0]["host"] == "10.0.0.1"

        with pytest.raises(OSError, match="Unexpected webhook hostname"):
            await resolver.resolve("127.0.0.1", 443)

    def test_webhook_connector_uses_static_resolver(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_url("https://10.0.0.1/webhook", allow_private=True)
        connector = svc._webhook_connector(target)

        try:
            assert isinstance(connector._resolver, StaticWebhookResolver)
        finally:
            connector.close()
