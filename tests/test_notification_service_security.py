"""Security tests for outbound webhook URL validation."""

import sys
import types

# Allow importing notification service in minimal test environments.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientTimeout = object  # type: ignore[attr-defined]
    sys.modules["aiohttp"] = aiohttp_stub

from core.notification_service import EnhancedNotificationService


def test_validate_outbound_webhook_rejects_non_https():
    service = EnhancedNotificationService()
    is_valid, error = service._validate_outbound_webhook_url("http://example.com/hook", "Slack")
    assert is_valid is False
    assert error is not None
    assert "HTTPS" in error


def test_validate_outbound_webhook_rejects_localhost():
    service = EnhancedNotificationService()
    is_valid, error = service._validate_outbound_webhook_url("https://localhost/hook", "Slack")
    assert is_valid is False
    assert error is not None
    assert "local address" in error


def test_validate_outbound_webhook_rejects_private_ip():
    service = EnhancedNotificationService()
    is_valid, error = service._validate_outbound_webhook_url("https://10.0.0.12/hook", "Slack")
    assert is_valid is False
    assert error is not None
    assert "non-public IP space" in error


def test_validate_outbound_webhook_accepts_public_dns(monkeypatch):
    service = EnhancedNotificationService()

    def _fake_getaddrinfo(*_args, **_kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", 443)),  # example.com public IP
        ]

    monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _fake_getaddrinfo)
    is_valid, error = service._validate_outbound_webhook_url("https://example.com/hook", "Slack")
    assert is_valid is True
    assert error is None


def test_validate_outbound_webhook_rejects_private_dns_resolution(monkeypatch):
    service = EnhancedNotificationService()

    def _fake_getaddrinfo(*_args, **_kwargs):
        return [
            (2, 1, 6, "", ("192.168.1.25", 443)),
        ]

    monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _fake_getaddrinfo)
    is_valid, error = service._validate_outbound_webhook_url("https://internal.example/hook", "Custom")
    assert is_valid is False
    assert error is not None
    assert "non-public IP space" in error
