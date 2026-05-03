"""Security tests for notification webhook URL validation."""

import pytest

from core.notification_service import DEFAULT_MAX_ATTACHMENT_BYTES, EnhancedNotificationService


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


class TestEmailAttachmentValidation:
    """Validate local file access controls for email attachments."""

    def test_allows_files_under_default_attachment_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        attachment = tmp_path / "data" / "report.json"
        attachment.parent.mkdir()
        attachment.write_text("{}", encoding="utf-8")

        assert svc._resolve_safe_attachment("data/report.json") == attachment.resolve()

    def test_rejects_paths_outside_allowed_attachment_directories(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        secret = tmp_path / ".env"
        secret.write_text("API_KEY=secret", encoding="utf-8")

        with pytest.raises(ValueError, match="outside allowed directories"):
            svc._resolve_safe_attachment(str(secret))

    def test_rejects_symlink_escape_from_allowed_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        attachment_dir = tmp_path / "data"
        attachment_dir.mkdir()
        link = attachment_dir / "secret-link.txt"
        link.symlink_to(outside)

        with pytest.raises(ValueError, match="outside allowed directories"):
            svc._resolve_safe_attachment(str(link))

    def test_rejects_oversized_attachments(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.project_root = tmp_path
        attachment = tmp_path / "data" / "large.bin"
        attachment.parent.mkdir()
        attachment.write_bytes(b"0" * (DEFAULT_MAX_ATTACHMENT_BYTES + 1))

        with pytest.raises(ValueError, match="exceeds maximum"):
            svc._resolve_safe_attachment(str(attachment))
