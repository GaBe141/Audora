"""Security tests for notification webhook validation."""

import socket

from core.notification_service import EnhancedNotificationService


class TestWebhookValidation:
    """Validate SSRF protections for webhook destinations."""

    def test_rejects_non_https_scheme(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("http://example.com/hook")
        assert is_valid is False
        assert "HTTPS" in error

    def test_rejects_localhost_destination(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://localhost/hook")
        assert is_valid is False
        assert "Localhost" in error

    def test_rejects_private_ip_destination(self):
        service = EnhancedNotificationService()
        is_valid, error = service._validate_webhook_url("https://127.0.0.1/hook")
        assert is_valid is False
        assert "Private or local network" in error

    def test_rejects_dns_resolution_to_private_ip(self, monkeypatch):
        service = EnhancedNotificationService()

        def _fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        is_valid, error = service._validate_webhook_url("https://webhook.example.com/hook")
        assert is_valid is False
        assert "Private or local network" in error

    def test_allows_public_https_destination(self, monkeypatch):
        service = EnhancedNotificationService()

        def _fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        is_valid, error = service._validate_webhook_url("https://webhook.example.com/hook")
        assert is_valid is True
        assert error == ""
