"""Security tests for notification webhook URL validation."""

import asyncio
import json

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


class TestNotificationConfigPersistence:
    """Ensure persisted notification configs do not leak credentials."""

    def test_save_config_strips_sensitive_values(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "password" not in saved["email"]
        assert "Authorization" not in saved["webhook"]["headers"]
        assert "api_key" not in saved["sms"]
        assert "api_secret" not in saved["sms"]


class TestEmailRenderingSecurity:
    """Validate that HTML email bodies escape untrusted notification text."""

    def test_html_email_escapes_message_content(self, monkeypatch):
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
                "username": "",
                "password": "",
                "recipients": ["security@example.com"],
            }
        )
        message = NotificationMessage(
            title="Security test",
            content="<script>alert('x')</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert sent_messages
        html_parts = [
            part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
            for part in sent_messages[0].walk()
            if part.get_content_type() == "text/html"
        ]
        assert html_parts
        assert "<script>" not in html_parts[0]
        assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in html_parts[0]
