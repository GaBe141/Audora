"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import EnhancedNotificationService, _PinnedHostResolver


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

    def test_validated_target_records_resolved_ips(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_target("https://10.0.0.1:8443/webhook", allow_private=True)

        assert target.url == "https://10.0.0.1:8443/webhook"
        assert target.hostname == "10.0.0.1"
        assert target.port == 8443
        assert target.resolved_ips == ("10.0.0.1",)

    def test_pinned_resolver_blocks_unvalidated_hosts(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_target("https://10.0.0.1/webhook", allow_private=True)
        resolver = _PinnedHostResolver(target)

        with pytest.raises(OSError, match="different hostname"):
            asyncio.run(resolver.resolve("169.254.169.254", 443))

    def test_pinned_resolver_reuses_validated_ip(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_target("https://10.0.0.1/webhook", allow_private=True)
        resolver = _PinnedHostResolver(target)

        results = asyncio.run(resolver.resolve("10.0.0.1", 443))

        assert results[0]["host"] == "10.0.0.1"
