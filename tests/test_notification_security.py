"""Security tests for notification webhook URL validation."""

from email import message_from_string

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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


class TestEmailSecurity:
    """Validate email body and attachment hardening."""

    def test_rejects_attachments_outside_allowed_directory(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["attachments"]["allowed_base_dir"] = str(allowed_dir)

        assert svc._resolve_attachment_path(str(outside_file)) is None

    def test_allows_attachments_inside_allowed_directory(self, tmp_path):
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        report_file = allowed_dir / "report.txt"
        report_file.write_text("safe", encoding="utf-8")

        svc = EnhancedNotificationService()
        svc.config["attachments"]["allowed_base_dir"] = str(allowed_dir)

        assert svc._resolve_attachment_path(str(report_file)) == report_file.resolve()

    @pytest.mark.asyncio
    async def test_escapes_html_email_content(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, server, port):
                self.server = server
                self.port = port

            def starttls(self):
                return None

            def login(self, username, password):
                return None

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        message = NotificationMessage(
            title="Security",
            content="hello</pre><script>alert(1)</script>",
            priority=NotificationPriority.HIGH,
            channels=[],
        )

        result = await svc._send_email(message)

        assert result["success"] is True
        assert sent_messages
        parsed = message_from_string(sent_messages[0].as_string())

        html_part = next(part for part in parsed.walk() if part.get_content_type() == "text/html")
        html_payload = html_part.get_payload(decode=True).decode()

        assert "<script>" not in html_payload
        assert "&lt;script&gt;" in html_payload
