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


class TestEmailAttachmentValidation:
    """Validate local file exfiltration protections for email attachments."""

    def test_allows_attachment_within_allowed_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        attachment = allowed_dir / "daily_report.txt"
        attachment.write_text("ok", encoding="utf-8")
        svc.config["email"]["attachment_allowed_dirs"] = [str(allowed_dir)]

        resolved = svc._resolve_email_attachment_path(str(attachment))
        assert resolved == attachment.resolve()

    def test_rejects_attachment_outside_allowed_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("super-secret", encoding="utf-8")
        svc.config["email"]["attachment_allowed_dirs"] = [str(allowed_dir)]

        with pytest.raises(ValueError, match="outside allowed attachment directories"):
            svc._resolve_email_attachment_path(str(outside_file))

    def test_rejects_path_traversal_outside_allowed_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        outside_file = tmp_path / "tokens.txt"
        outside_file.write_text("token", encoding="utf-8")
        traversal_path = allowed_dir / ".." / "tokens.txt"
        svc.config["email"]["attachment_allowed_dirs"] = [str(allowed_dir)]

        with pytest.raises(ValueError, match="outside allowed attachment directories"):
            svc._resolve_email_attachment_path(str(traversal_path))

    def test_rejects_oversized_attachment(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "reports"
        allowed_dir.mkdir()
        large_file = allowed_dir / "large.bin"
        large_file.write_bytes(b"x" * (2 * 1024 * 1024))
        svc.config["email"]["attachment_allowed_dirs"] = [str(allowed_dir)]
        svc.config["email"]["max_attachment_size_mb"] = 1

        with pytest.raises(ValueError, match="maximum allowed size"):
            svc._resolve_email_attachment_path(str(large_file))
