"""Security tests for notification webhook and attachment validation."""

import pytest

from core.notification_service import EnhancedNotificationService


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


class TestAttachmentValidation:
    """Validate secure attachment path controls."""

    def test_rejects_attachments_when_feature_disabled(self, tmp_path):
        svc = EnhancedNotificationService()
        attachment = tmp_path / "report.txt"
        attachment.write_text("hello", encoding="utf-8")

        with pytest.raises(ValueError, match="disabled"):
            svc._validate_attachment_path(str(attachment))

    def test_rejects_attachment_outside_allowed_dirs(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_ENABLE_EMAIL_ATTACHMENTS", "true")
        allowed_dir = tmp_path / "allowed"
        disallowed_dir = tmp_path / "outside"
        allowed_dir.mkdir()
        disallowed_dir.mkdir()
        monkeypatch.setenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", str(allowed_dir))

        attachment = disallowed_dir / "secret.txt"
        attachment.write_text("sensitive", encoding="utf-8")

        with pytest.raises(ValueError, match="outside allowed attachment directories"):
            svc._validate_attachment_path(str(attachment))

    def test_allows_attachment_inside_allowed_dirs(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_ENABLE_EMAIL_ATTACHMENTS", "true")
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        monkeypatch.setenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", str(allowed_dir))

        attachment = allowed_dir / "report.txt"
        attachment.write_text("ok", encoding="utf-8")

        validated = svc._validate_attachment_path(str(attachment))
        assert validated == attachment.resolve()
