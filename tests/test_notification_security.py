"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    _RestrictedAddressResolver,
)


class _FakeResolver:
    """Simple async resolver test double."""

    def __init__(self, records):
        self.records = records
        self.closed = False

    async def resolve(self, host, port=0, family=0):
        return self.records

    async def close(self):
        self.closed = True


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

    def test_validate_resolved_ips_rejects_private_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_resolved_ips({"10.1.2.3"}, allow_private=False)

    def test_validate_resolved_ips_allows_public_addresses(self):
        svc = EnhancedNotificationService()
        svc._validate_resolved_ips({"8.8.8.8"}, allow_private=False)

    def test_restricted_resolver_blocks_private_addresses(self):
        svc = EnhancedNotificationService()
        resolver = _RestrictedAddressResolver(
            allow_private=False,
            is_restricted_ip=svc._is_restricted_ip,
        )
        resolver._resolver = _FakeResolver([{"host": "10.0.0.5"}])

        with pytest.raises(ValueError, match="private or restricted"):
            asyncio.run(resolver.resolve("example.com", 443))
        asyncio.run(resolver.close())

    def test_restricted_resolver_allows_public_addresses(self):
        svc = EnhancedNotificationService()
        resolver = _RestrictedAddressResolver(
            allow_private=False,
            is_restricted_ip=svc._is_restricted_ip,
        )
        fake = _FakeResolver([{"host": "1.1.1.1"}])
        resolver._resolver = fake

        resolved = asyncio.run(resolver.resolve("example.com", 443))
        assert resolved[0]["host"] == "1.1.1.1"
        asyncio.run(resolver.close())
        assert fake.closed is True
