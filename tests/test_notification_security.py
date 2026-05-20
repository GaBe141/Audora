"""Security tests for notification webhook URL validation."""

import asyncio
import json

import pytest

from core.notification_service import EnhancedNotificationService, NotificationPriority


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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://token@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationSecretPersistence:
    """Validate notification config persistence does not write secrets."""

    def test_save_config_redacts_secret_values(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret-token"
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert saved["email"]["password"] == ""
        assert saved["slack"]["webhook_url"] == ""
        assert saved["webhook"]["headers"]["Authorization"] == ""


class TestEmailAttachmentSafety:
    """Validate email attachment reads are confined to the attachment directory."""

    def test_attachment_must_be_inside_configured_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        inside = allowed_dir / "report.txt"
        inside.write_text("safe")
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))
        svc = EnhancedNotificationService()

        assert svc._safe_attachment_path("report.txt") == inside.resolve()
        assert svc._safe_attachment_path(str(outside)) is None

    def test_html_email_content_is_escaped(self):
        svc = EnhancedNotificationService()
        escaped = svc.template_env.from_string("{{ content }}").render(
            content="<script>alert(1)</script>"
        )
        assert escaped == "&lt;script&gt;alert(1)&lt;/script&gt;"


class TestSmtpSafety:
    """Validate SMTP credentials are not sent without TLS."""

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["recipient@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )

        result = asyncio.run(
            svc._send_email(
                message=type(
                    "Message",
                    (),
                    {
                        "title": "Test",
                        "content": "Body",
                        "priority": NotificationPriority.LOW,
                        "attachments": None,
                        "template_vars": None,
                    },
                )()
            )
        )

        assert result == {"success": False, "error": "SMTP authentication requires TLS"}
