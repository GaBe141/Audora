"""Security tests for notification service hardening."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


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
    """Minimal fake SMTP client used for transport-security tests."""

    def __init__(self, _host, _port, timeout=None):
        self.timeout = timeout
        self.started_tls = False
        self.tls_context = None
        self.quit_called = False
        self.sent_message = None

    def ehlo(self):
        return None

    def starttls(self, context=None):
        self.started_tls = True
        self.tls_context = context
        return None

    def login(self, _username, _password):
        return None

    def send_message(self, msg):
        self.sent_message = msg
        return None

    def quit(self):
        self.quit_called = True
        return None


class TestEmailSecurity:
    """Validate email transport and header-injection protections."""

    def _build_message(self, title: str = "Test alert") -> NotificationMessage:
        return NotificationMessage(
            title=title,
            content="Security test message",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

    def test_blocks_insecure_smtp_without_override(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "noreply@example.com",
                "recipients": ["user@example.com"],
                "use_tls": False,
            }
        )

        fake_client = _FakeSMTP("smtp.example.com", 587)
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: fake_client,
        )
        monkeypatch.delenv("AUDORA_ALLOW_INSECURE_SMTP", raising=False)

        result = asyncio.run(svc._send_email(self._build_message()))

        assert result["success"] is False
        assert "Insecure SMTP without TLS is disabled" in result["error"]
        assert fake_client.started_tls is False
        assert fake_client.quit_called is True

    def test_uses_verified_tls_context_for_starttls(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "noreply@example.com",
                "recipients": ["user@example.com"],
                "use_tls": True,
            }
        )

        fake_client = _FakeSMTP("smtp.example.com", 587)
        tls_context_sentinel = object()

        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: fake_client,
        )
        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: tls_context_sentinel,
        )

        result = asyncio.run(svc._send_email(self._build_message()))

        assert result["success"] is True
        assert fake_client.started_tls is True
        assert fake_client.tls_context is tls_context_sentinel
        assert fake_client.sent_message is not None

    def test_rejects_email_header_injection(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "from_address": "noreply@example.com",
                "recipients": ["victim@example.com"],
                "use_tls": True,
            }
        )

        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: pytest.fail("SMTP should not be called for invalid headers"),
        )

        result = asyncio.run(svc._send_email(self._build_message("safe\nBcc:evil@example.com")))

        assert result["success"] is False
        assert "header injection detected" in result["error"]
