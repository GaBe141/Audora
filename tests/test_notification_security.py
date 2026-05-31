"""Security tests for notification webhook URL validation."""

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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestEmailSecurity:
    """Validate TLS requirements for SMTP credentials and HTML escaping."""

    def test_refuses_smtp_authentication_without_tls(self, monkeypatch):
        smtp_instances = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                self.logged_in = False
                self.quit_called = False
                smtp_instances.append(self)

            def login(self, *_args, **_kwargs):
                self.logged_in = True

            def quit(self):
                self.quit_called = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }

        message = NotificationMessage(
            title="Alert",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        import asyncio

        result = asyncio.run(svc._send_email(message))

        assert result == {
            "success": False,
            "error": "Refusing to authenticate to SMTP without TLS",
        }
        assert smtp_instances[0].logged_in is False
        assert smtp_instances[0].quit_called is True

    def test_escapes_html_email_body(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *args, **kwargs):
                assert "context" in kwargs

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }

        message = NotificationMessage(
            title="Alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        import asyncio

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        html_part = sent_messages[0].get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_part
