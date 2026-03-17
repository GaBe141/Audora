"""Security regression tests for notification service hardening."""

import asyncio
import socket
import ssl

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _build_message() -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="message",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.CONSOLE],
    )


def test_validate_outbound_url_rejects_non_https():
    service = EnhancedNotificationService()
    try:
        service._validate_outbound_url("http://example.com/hook")
        assert False, "Expected ValueError for non-HTTPS URL"
    except ValueError as exc:
        assert "HTTPS" in str(exc)


def test_validate_outbound_url_rejects_private_ip_resolution(monkeypatch):
    service = EnhancedNotificationService()

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        service._validate_outbound_url("https://example.com/hook")
        assert False, "Expected ValueError for private IP target"
    except ValueError as exc:
        assert "disallowed" in str(exc)


def test_validate_outbound_url_accepts_public_ip_resolution(monkeypatch):
    service = EnhancedNotificationService()

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    service._validate_outbound_url("https://example.com/hook")


def test_send_webhook_rejects_insecure_url_without_network_call():
    service = EnhancedNotificationService()
    service.config["webhook"]["url"] = "http://example.com/hook"

    result = asyncio.run(service._send_webhook(_build_message()))
    assert result["success"] is False
    assert "HTTPS" in result["error"]


def test_send_email_uses_verified_tls_context(monkeypatch):
    service = EnhancedNotificationService()
    service.config["email"] = {
        "smtp_server": "smtp.example.com",
        "port": 587,
        "username": "",
        "password": "",
        "from_address": "noreply@example.com",
        "recipients": ["alerts@example.com"],
        "use_tls": True,
    }

    sent = {}

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            self.tls_context = None

        def ehlo(self):
            return None

        def starttls(self, context=None):
            self.tls_context = context

        def login(self, *_args, **_kwargs):
            return None

        def send_message(self, *_args, **_kwargs):
            sent["ok"] = True

        def quit(self):
            return None

    fake_client = FakeSMTP()
    monkeypatch.setattr("core.notification_service.smtplib.SMTP", lambda *_args, **_kwargs: fake_client)

    result = asyncio.run(service._send_email(_build_message()))
    assert result["success"] is True
    assert sent.get("ok") is True
    assert isinstance(fake_client.tls_context, ssl.SSLContext)
