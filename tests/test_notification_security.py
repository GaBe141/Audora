"""Security tests for notification webhook URL validation."""

import asyncio
import smtplib
from email import message_from_string
from email.policy import default

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class DummySMTP:
    """Capture outbound email without making a network connection."""

    sent_messages = []

    def __init__(self, smtp_server, port):
        self.smtp_server = smtp_server
        self.port = port

    def starttls(self):
        return None

    def login(self, username, password):
        return None

    def send_message(self, msg):
        self.sent_messages.append(msg)

    def quit(self):
        return None


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


class TestEmailRenderingSecurity:
    """Validate notification email rendering does not inject HTML."""

    def test_email_html_part_escapes_message_content(self, monkeypatch):
        DummySMTP.sent_messages = []
        monkeypatch.setattr(smtplib, "SMTP", DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security check",
            content="<img src=x onerror=alert(1)>\n<script>alert(2)</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert len(DummySMTP.sent_messages) == 1
        parsed = message_from_string(DummySMTP.sent_messages[0].as_string(), policy=default)
        html_part = next(part for part in parsed.walk() if part.get_content_type() == "text/html")
        html_body = html_part.get_content()
        assert "<img src=x onerror=alert(1)>" not in html_body
        assert "<script>alert(2)</script>" not in html_body
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_body
        assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html_body
