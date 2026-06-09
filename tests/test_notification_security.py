"""Security tests for notification webhook URL validation."""

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


class TestAttachmentPathValidation:
    """Validate local file exposure protections for notification attachments."""

    def test_allows_attachment_inside_configured_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "attachments"
        allowed_dir.mkdir()
        report = allowed_dir / "report.txt"
        report.write_text("safe report", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))

        svc = EnhancedNotificationService()

        assert svc._validate_attachment_path(str(report)) == report.resolve()

    def test_rejects_attachment_outside_configured_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "attachments"
        allowed_dir.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("do not send", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))

        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="outside the allowed directory"):
            svc._validate_attachment_path(str(secret))

    def test_rejects_symlink_escape_from_configured_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "attachments"
        allowed_dir.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("do not send", encoding="utf-8")
        link = allowed_dir / "linked_secret.txt"
        link.symlink_to(secret)
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))

        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="outside the allowed directory"):
            svc._validate_attachment_path(str(link))
