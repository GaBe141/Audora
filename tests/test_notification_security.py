"""Security tests for notification webhook URL validation."""

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


class TestNotificationEmailSecurity:
    """Validate secure email rendering and recipient handling."""

    def test_email_html_part_escapes_untrusted_content(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "u",
                "password": "p",
                "recipients": [" user@example.com "],
                "use_tls": False,
            }
        )

        sent_messages = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=30):
                self.host = host
                self.port = port
                self.timeout = timeout

            def ehlo(self):
                return None

            def starttls(self, context=None):
                return None

            def login(self, username, password):
                return None

            def send_message(self, msg, to_addrs=None):
                sent_messages.append((msg, to_addrs))

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        msg = NotificationMessage(
            title="test",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is True
        assert result["recipients"] == 1
        assert sent_messages

        rendered = sent_messages[0][0].as_string()
        assert "<script>alert(1)</script>" not in rendered
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered

    def test_email_filters_blank_recipients(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["", "   "],
            }
        )
        msg = NotificationMessage(
            title="test",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is False
        assert "not configured" in result["error"].lower()
