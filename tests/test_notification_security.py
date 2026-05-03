"""Security tests for notification webhook URL validation."""

import asyncio
from email import message_from_string

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

    def test_rejects_unsafe_attachment_paths(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["attachment_base_dir"] = str(tmp_path / "allowed")

        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("do not attach", encoding="utf-8")

        with pytest.raises(ValueError, match="attachment directory"):
            svc._resolve_attachment_path(str(secret_file))

    def test_allows_attachment_inside_safe_directory(self, tmp_path):
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        report_file = allowed_dir / "report.txt"
        report_file.write_text("safe report", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["attachment_base_dir"] = str(allowed_dir)

        assert svc._resolve_attachment_path(str(report_file)) == report_file.resolve()

    def test_escapes_html_email_content(self, monkeypatch):
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

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        message = NotificationMessage(
            title="test",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        rendered = sent_messages[0].as_string()
        parsed = message_from_string(rendered)
        html_part = next(part for part in parsed.walk() if part.get_content_type() == "text/html")
        html_payload = html_part.get_payload(decode=True).decode()
        assert "<script>" not in html_payload
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_payload
