"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import EnhancedNotificationService, RestrictedIPResolver


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

    def test_restricted_resolver_rejects_rebound_private_ip(self, monkeypatch):
        async def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", 443),
                )
            ]

        class FakeLoop:
            getaddrinfo = fake_getaddrinfo

        monkeypatch.setattr("asyncio.get_running_loop", lambda: FakeLoop())

        svc = EnhancedNotificationService()
        resolver = RestrictedIPResolver(svc._is_restricted_ip)

        with pytest.raises(OSError, match="private or restricted"):
            asyncio.run(resolver.resolve("example.com", 443))

    def test_restricted_resolver_allows_public_ip(self, monkeypatch):
        async def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        class FakeLoop:
            getaddrinfo = fake_getaddrinfo

        monkeypatch.setattr("asyncio.get_running_loop", lambda: FakeLoop())

        svc = EnhancedNotificationService()
        resolver = RestrictedIPResolver(svc._is_restricted_ip)

        assert asyncio.run(resolver.resolve("example.com", 443)) == [
            {
                "hostname": "example.com",
                "host": "93.184.216.34",
                "port": 443,
                "family": socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": 0,
            }
        ]
