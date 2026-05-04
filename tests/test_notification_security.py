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

    def test_rejects_unsafe_webhook_targets_before_persisting(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "http://example.com/webhook"

        with pytest.raises(ValueError, match="HTTPS"):
            svc.save_config(str(tmp_path / "notification_config.json"))


class TestEmailRendering:
    """Validate generated email HTML does not execute notification content."""

    def test_email_html_escapes_untrusted_content(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self):
                pass

            def login(self, *_args, **_kwargs):
                pass

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["recipient@example.com"],
                "username": "",
                "password": "",
            }
        )
        message = NotificationMessage(
            title="Escaping test",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        html_part = sent_messages[0].get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode()
        assert "<script>" not in html_body
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_body
