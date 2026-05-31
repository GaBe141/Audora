"""Security tests for notification webhook URL validation and email handling."""

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

    def test_private_ip_targets_cannot_be_bypassed_by_env(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")


class TestEmailSecurity:
    """Validate email notifications do not leak files or inject HTML."""

    def test_email_html_body_escapes_message_content(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self):
                pass

            def login(self, *_args, **_kwargs):
                pass

            def send_message(self, message):
                sent_messages.append(message)

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "from_address": "audora@example.com",
            }
        )

        message = NotificationMessage(
            title="Security test",
            content='hello</pre><script>alert("xss")</script>',
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        html_part = sent_messages[0].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
        assert "&lt;/pre&gt;" in html_part

    def test_rejects_email_attachments_outside_attachment_dir(self, tmp_path):
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")
        attachment_root = tmp_path / "exports"
        attachment_root.mkdir()

        svc = EnhancedNotificationService()
        svc.config["attachment_dir"] = str(attachment_root)
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "from_address": "audora@example.com",
            }
        )
        message = NotificationMessage(
            title="Attachment test",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
            attachments=[str(outside_file)],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "attachments must be inside" in result["error"]
