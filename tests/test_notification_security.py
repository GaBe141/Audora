"""Security tests for notification webhook URL validation."""

import socket

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

    def test_validated_target_preserves_resolved_ips(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, **kwargs):
            assert host == "example.com"
            assert port == 443
            assert kwargs["proto"] > 0
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
            ]

        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)

        target = svc._validate_webhook_target("https://example.com/webhook")

        assert target.hostname == "example.com"
        assert target.resolved_ips == ("93.184.216.34",)


class TestPinnedWebhookResolver:
    """Ensure outbound requests use only pre-validated DNS answers."""

    @pytest.mark.asyncio
    async def test_resolver_rejects_unvalidated_hostname(self):
        resolver = _PinnedWebhookResolver("example.com", ("93.184.216.34",))

        with pytest.raises(OSError, match="unvalidated"):
            await resolver.resolve("metadata.google.internal", 443)
