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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationConfigAndEmailSafety:
    """Config path confinement, header sanitization, and SMTP TLS requirements."""

    def test_save_config_rejects_path_escape(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config").mkdir()
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(tmp_path / "evil.json"))

    def test_sanitizes_crlf_in_email_headers(self):
        svc = EnhancedNotificationService()
        assert "\r" not in svc._sanitize_email_header("Subject\r\nBcc: evil@example.com")
        assert "\n" not in svc._sanitize_email_header("Subject\r\nBcc: evil@example.com")

    def test_rejects_attachments_outside_allowed_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("classified", encoding="utf-8")
        assert svc._is_allowed_attachment(str(secret)) is False

    def test_refuses_smtp_authentication_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="alert",
                    content="body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )
        assert result["success"] is False
        assert "TLS" in result["error"]
