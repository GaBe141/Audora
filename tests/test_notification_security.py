"""Security tests for notification webhook URL validation."""

import asyncio
import socket

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

    def test_rejects_hostname_that_resolves_to_private_ip(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, type, proto):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://public-looking.example/webhook")

    def test_prepared_webhook_request_pins_validated_dns_result(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, type, proto):
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
        url, connector = svc._prepare_webhook_request("https://example.com/webhook")

        async def resolve_pinned_address():
            try:
                addresses = await connector._resolver.resolve("example.com", 443)
            finally:
                await connector.close()
            return addresses

        addresses = asyncio.run(resolve_pinned_address())

        assert url == "https://example.com/webhook"
        assert addresses[0]["host"] == "93.184.216.34"

    def test_private_webhook_override_requires_local_environment(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        monkeypatch.delenv("AUDORA_ENV", raising=False)

        assert svc._allow_private_webhooks() is False

        monkeypatch.setenv("AUDORA_ENV", "development")
        assert svc._allow_private_webhooks() is True
