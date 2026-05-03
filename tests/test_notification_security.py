"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import EnhancedNotificationService, RestrictedWebhookResolver


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

    def test_rejects_slack_webhook_url_outside_slack_hosts(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="hostname is not allowed"):
            svc._validate_webhook_url(
                "https://example.com/services/T000/B000/secret",
                allowed_hosts={"hooks.slack.com", "hooks.slack-gov.com"},
            )

    def test_allows_slack_webhook_host(self):
        svc = EnhancedNotificationService()
        url = "https://hooks.slack.com/services/T000/B000/secret"
        assert (
            svc._validate_webhook_url(
                url,
                allowed_hosts={"hooks.slack.com", "hooks.slack-gov.com"},
            )
            == url
        )

    def test_rejects_subdomain_of_allowed_webhook_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="hostname is not allowed"):
            svc._validate_webhook_url(
                "https://evil.hooks.slack.com/services/T000/B000/secret",
                allowed_hosts={"hooks.slack.com", "hooks.slack-gov.com"},
            )


class FakeResolver:
    """Minimal aiohttp resolver stub for testing connection-time IP checks."""

    def __init__(self, hosts):
        self.hosts = hosts

    async def resolve(self, _host, port=0, family=socket.AF_INET):
        return self.hosts

    async def close(self):
        return None


def test_restricted_resolver_rejects_private_dns_results():
    resolver = RestrictedWebhookResolver()
    resolver._resolver = FakeResolver(
        [
            {
                "hostname": "example.com",
                "host": "127.0.0.1",
                "port": 443,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
        ]
    )

    with pytest.raises(OSError, match="private or restricted"):
        asyncio.run(resolver.resolve("example.com", 443))


def test_restricted_resolver_allows_private_dns_results_when_enabled():
    hosts = [
        {
            "hostname": "example.com",
            "host": "127.0.0.1",
            "port": 443,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }
    ]
    resolver = RestrictedWebhookResolver(allow_private=True)
    resolver._resolver = FakeResolver(hosts)

    assert asyncio.run(resolver.resolve("example.com", 443)) == hosts
