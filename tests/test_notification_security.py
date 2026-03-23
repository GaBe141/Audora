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


class TestNotificationConfigPersistence:
    """Ensure sensitive notification secrets are not persisted."""

    def test_sanitizes_sensitive_fields_before_save(self):
        svc = EnhancedNotificationService()
        cfg = {
            "email": {"smtp_server": "smtp.example.com", "password": "secret"},
            "slack": {"webhook_url": "https://hooks.slack.com/services/ABC/DEF/GHI"},
            "discord": {"webhook_url": "https://discord.com/api/webhooks/abc/secret"},
            "webhook": {
                "url": "https://example.com/hooks/secret",
                "headers": {"Authorization": "Bearer token", "Content-Type": "application/json"},
            },
            "sms": {"api_key": "key", "api_secret": "secret"},
        }
        sanitized = svc._sanitize_config_for_persistence(cfg)

        assert sanitized["email"]["password"] == ""
        assert sanitized["slack"]["webhook_url"] == ""
        assert sanitized["discord"]["webhook_url"] == ""
        assert sanitized["webhook"]["url"] == ""
        assert "Authorization" not in sanitized["webhook"]["headers"]
        assert sanitized["sms"]["api_key"] == ""
        assert sanitized["sms"]["api_secret"] == ""


class TestNotificationAttachmentSafety:
    """Validate attachment security checks."""

    def test_allows_safe_attachment_under_project_root(self, tmp_path, monkeypatch):
        project_root = tmp_path / "project"
        project_root.mkdir()
        attachment = project_root / "report.txt"
        attachment.write_text("safe attachment", encoding="utf-8")
        monkeypatch.chdir(project_root)

        svc = EnhancedNotificationService()
        assert svc._is_safe_attachment(str(attachment))

    def test_rejects_attachment_outside_project_root(self, tmp_path, monkeypatch):
        project_root = tmp_path / "project"
        project_root.mkdir()
        outside_attachment = tmp_path / "outside.txt"
        outside_attachment.write_text("unsafe attachment", encoding="utf-8")
        monkeypatch.chdir(project_root)

        svc = EnhancedNotificationService()
        assert not svc._is_safe_attachment(str(outside_attachment))

    def test_rejects_attachment_with_disallowed_extension(self, tmp_path, monkeypatch):
        project_root = tmp_path / "project"
        project_root.mkdir()
        attachment = project_root / "secret.exe"
        attachment.write_bytes(b"binary")
        monkeypatch.chdir(project_root)

        svc = EnhancedNotificationService()
        assert not svc._is_safe_attachment(str(attachment))


class TestMessageDeduplicationKey:
    """Ensure deduplication keys are deterministic."""

    def test_generate_message_key_is_deterministic(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.CONSOLE],
        )
        key_one = svc._generate_message_key(message)
        key_two = svc._generate_message_key(message)

        assert key_one == key_two
        # 64 hex chars + ":" + priority label
        assert len(key_one.split(":")[0]) == 64
