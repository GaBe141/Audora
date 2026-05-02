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

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_returns_validated_ips_for_pinned_webhook_connections(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            assert host == "example.com"
            assert port == 443
            assert proto == socket.IPPROTO_TCP
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

        url, resolved_ips = svc._resolve_webhook_url("https://example.com/webhook")

        assert url == "https://example.com/webhook"
        assert resolved_ips == {"93.184.216.34"}

    def test_rejects_hostname_when_any_resolved_ip_is_private(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", port),
                ),
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                ),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        with pytest.raises(ValueError, match="private or restricted"):
            svc._resolve_webhook_url("https://example.com/webhook")
