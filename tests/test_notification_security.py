"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

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

    def test_rejects_loopback_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/webhook", allow_private=True)

    def test_rejects_link_local_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_rejects_credentials_obfuscated_literals_and_metadata_hosts(self):
        svc = EnhancedNotificationService()
        blocked = [
            "https://user:pass@example.com/hook",
            "https://2130706433/hook",
            "https://0x7f000001/hook",
            "https://0177.0.0.1/hook",
            "https://127.1/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://evil.localhost/hook",
        ]
        for url in blocked:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_config_path_cannot_escape_config_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(tmp_path / "notification_config.json"))

    def test_smtp_always_verifies_tls_and_sanitizes_content(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "recipients": ["listener@example.com"],
                "username": "",
                "password": "",
                "use_tls": False,
                "from_address": "from@example.com",
            }
        )
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["context"] = context

            def send_message(self, message):
                captured["message"] = message

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Hello\r\nBcc: evil@example.com",
                    content="<script>alert(1)</script>",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                    attachments=["/etc/passwd"],
                )
            )
        )
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        message = captured["message"]
        assert "\r" not in message["Subject"]
        assert "\n" not in message["Subject"]
        html_part = message.get_payload()[-1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
        assert len(message.get_payload()) == 2
