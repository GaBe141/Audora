"""Security tests for notification webhook URL and transport validation."""

import asyncio
import ssl

import pytest

from core.notification_service import EnhancedNotificationService, NotificationMessage, NotificationPriority


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


class TestEmailTransportSecurity:
    """Validate secure SMTP transport behavior."""

    def test_email_uses_starttls_with_verified_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["recipients"] = ["security@example.com"]
        svc.config["email"]["use_tls"] = True

        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, _host, _port):
                captured["smtp_init"] = True

            def ehlo(self):
                captured["ehlo_called"] = True

            def starttls(self, context=None):
                captured["tls_context"] = context

            def login(self, _username, _password):
                return None

            def send_message(self, _msg):
                captured["message_sent"] = True

            def quit(self):
                captured["quit_called"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        message = NotificationMessage(
            title="TLS security test",
            content="validate SMTP transport security",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert captured.get("message_sent") is True
        assert isinstance(captured.get("tls_context"), ssl.SSLContext)
        tls_context = captured["tls_context"]
        assert tls_context.verify_mode == ssl.CERT_REQUIRED
        assert tls_context.check_hostname is True
