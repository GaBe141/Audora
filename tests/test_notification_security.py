"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import aiohttp
import pytest

from core.notification_service import EnhancedNotificationService


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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="user credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_pins_validated_dns_records(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, *args, **kwargs):
            assert host == "hooks.example.com"
            assert port == 443
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        async def prepare_and_resolve():
            target = svc._prepare_webhook_target("https://hooks.example.com/webhook")
            try:
                assert target.url == "https://hooks.example.com/webhook"
                resolver = target.connector._resolver
                assert not isinstance(resolver, aiohttp.DefaultResolver)

                return await resolver.resolve("hooks.example.com", 443)
            finally:
                await target.connector.close()

        records = asyncio.run(prepare_and_resolve())
        assert records[0]["host"] == "93.184.216.34"
