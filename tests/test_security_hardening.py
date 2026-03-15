"""Regression tests for security hardening changes."""

import asyncio
import importlib
import socket
import ssl

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from gui.app import _validate_webhook_url

gui_app_module = importlib.import_module("gui.app")


class TestWebhookUrlValidation:
    """Validate webhook URL safety checks."""

    def test_slack_requires_official_host(self):
        ok, _ = _validate_webhook_url("https://hooks.slack.com/services/T000/B000/abc", "slack")
        assert ok is True

        ok, msg = _validate_webhook_url("https://evil.example.com/hook", "slack")
        assert ok is False
        assert "hooks.slack.com" in msg

    def test_custom_webhook_rejects_localhost(self):
        ok, msg = _validate_webhook_url("https://localhost/internal", "webhook")
        assert ok is False
        assert "localhost" in msg.lower()

    def test_custom_webhook_rejects_private_resolution(self, monkeypatch):
        def fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]

        monkeypatch.setattr(gui_app_module.socket, "getaddrinfo", fake_getaddrinfo)
        ok, msg = _validate_webhook_url("https://example.com/hook", "webhook")
        assert ok is False
        assert "private/internal" in msg

    def test_custom_webhook_accepts_public_resolution(self, monkeypatch):
        def fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        monkeypatch.setattr(gui_app_module.socket, "getaddrinfo", fake_getaddrinfo)
        ok, normalized = _validate_webhook_url("https://example.com/hook", "webhook")
        assert ok is True
        assert normalized == "https://example.com/hook"


class TestNotificationTransportSecurity:
    """Check secure notification transport defaults."""

    def test_webhook_defaults_do_not_include_authorization_header(self):
        svc = EnhancedNotificationService()
        headers = svc.config["webhook"]["headers"]
        assert "Authorization" not in headers

    def test_smtp_starttls_uses_verifying_context(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                return None

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, *_args, **_kwargs):
                return None

            def send_message(self, *_args, **_kwargs):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "noreply@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }

        message = NotificationMessage(
            title="test",
            content="security",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        tls_context = captured["context"]
        assert isinstance(tls_context, ssl.SSLContext)
        assert tls_context.verify_mode == ssl.CERT_REQUIRED
        assert tls_context.check_hostname is True
