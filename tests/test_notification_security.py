"""Security tests for notification service hardening."""

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
    """Validate attachment path restrictions to prevent file exfiltration."""

    def test_resolve_attachment_path_allows_files_inside_allowed_dir(self, tmp_path, monkeypatch):
        attachment_dir = tmp_path / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)
        allowed_file = attachment_dir / "report.txt"
        allowed_file.write_text("ok", encoding="utf-8")

        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(attachment_dir))
        svc = EnhancedNotificationService()

        resolved = svc._resolve_attachment_path("report.txt")
        assert resolved == allowed_file.resolve()

    def test_resolve_attachment_path_rejects_directory_traversal(self, tmp_path, monkeypatch):
        attachment_dir = tmp_path / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(attachment_dir))
        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="outside the allowed attachment directory"):
            svc._resolve_attachment_path("../secret.txt")
