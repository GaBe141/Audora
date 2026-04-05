"""Security tests for notification transport hardening."""

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


class _FakeSMTP:
    """Simple SMTP stub to capture TLS and auth usage."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.starttls_context = None
        self.logged_in = False
        self.sent = False
        _FakeSMTP.instances.append(self)

    def starttls(self, context=None):
        self.starttls_context = context

    def login(self, _username, _password):
        self.logged_in = True

    def send_message(self, _msg):
        self.sent = True

    def quit(self):
        return None


class TestSmtpTransportSecurity:
    """Validate SMTP transport security controls."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "alice",
            "password": "secret",
            "recipients": ["team@example.com"],
            "from_address": "bot@example.com",
            "use_tls": False,
        }
        message = NotificationMessage(
            title="Security test",
            content="body",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )

        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_uses_verified_tls_context_for_starttls(self, monkeypatch):
        _FakeSMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "alice",
            "password": "secret",
            "recipients": ["team@example.com"],
            "from_address": "bot@example.com",
            "use_tls": True,
        }
        message = NotificationMessage(
            title="Security test",
            content="body",
            priority=NotificationPriority.MEDIUM,
            channels=[],
        )

        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert _FakeSMTP.instances, "SMTP client should be instantiated"

        smtp = _FakeSMTP.instances[-1]
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.logged_in is True
        assert smtp.sent is True
