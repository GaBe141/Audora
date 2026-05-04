"""Security tests for notification delivery hardening."""

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


class TestEmailNotificationRendering:
    """Validate untrusted notification text cannot inject HTML."""

    @pytest.mark.asyncio
    async def test_escapes_plain_text_content_in_html_email(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, smtp_server, port):
                self.smtp_server = smtp_server
                self.port = port

            def starttls(self):
                return None

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "",
                "password": "",
            }
        )

        message = NotificationMessage(
            title="Viral Prediction",
            content='Track <img src=x onerror="alert(1)"> by Artist & Co',
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = await svc._send_email(message)

        assert result["success"] is True
        html_part = captured["msg"].get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode()
        assert "<img" not in html_body
        assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_body
        assert "Artist &amp; Co" in html_body
