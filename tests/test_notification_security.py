"""Security tests for notification webhook URL validation."""

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

    def test_validate_webhook_url_returns_pinned_addresses(self):
        svc = EnhancedNotificationService()
        url = "https://example.com/webhook"

        validated_url, hostname, addresses = svc._validate_webhook_url(url)

        assert validated_url == url
        assert hostname == "example.com"
        assert addresses
        assert all("host" in address for address in addresses)

    @pytest.mark.asyncio
    async def test_webhook_connector_uses_pinned_resolver(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        _, connector = svc._webhook_connector("https://example.com/webhook")
        try:
            resolved = await connector._resolver.resolve("example.com", 443)
            assert resolved[0]["host"] == "93.184.216.34"
        finally:
            await connector.close()
