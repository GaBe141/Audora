"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import EnhancedNotificationService, PinnedWebhookResolver


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

    def test_rejects_urls_with_userinfo(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="user info"):
            svc._validate_webhook_url("https://user:password@example.com/webhook")

    def test_pins_resolved_webhook_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            assert host == "example.com"
            assert port == 443
            assert proto == socket.IPPROTO_TCP
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        target = svc._validate_webhook_target("https://example.com/webhook")

        assert target.url == "https://example.com/webhook"
        assert target.hostname == "example.com"
        assert target.port == 443
        assert target.resolved_ips == ("93.184.216.34",)

    def test_pinned_resolver_rejects_unvalidated_hostnames(self):
        resolver = PinnedWebhookResolver("example.com", 443, ("93.184.216.34",))

        with pytest.raises(OSError, match="Unexpected webhook hostname"):
            asyncio.run(resolver.resolve("localhost", 443))

    def test_pinned_resolver_returns_only_pinned_addresses(self):
        resolver = PinnedWebhookResolver("example.com", 443, ("93.184.216.34",))

        records = asyncio.run(resolver.resolve("example.com", 443))

        assert records == [
            {
                "hostname": "example.com",
                "host": "93.184.216.34",
                "port": 443,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]
