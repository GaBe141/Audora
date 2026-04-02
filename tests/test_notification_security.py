"""Security tests for notification webhook URL validation and file handling."""

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
    """Validate attachment path restrictions to prevent file exfiltration."""

    def test_allows_attachment_inside_configured_directory(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        attachment_file = allowed_dir / "report.txt"
        attachment_file.write_text("safe content", encoding="utf-8")

        monkeypatch.setenv("AUDORA_NOTIFICATION_ALLOWED_ATTACHMENT_DIRS", str(allowed_dir))

        resolved = svc._resolve_safe_attachment_path(str(attachment_file))
        assert resolved == attachment_file.resolve()

    def test_rejects_missing_attachment_file(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_NOTIFICATION_ALLOWED_ATTACHMENT_DIRS", str(tmp_path))
        assert svc._resolve_safe_attachment_path("this-file-does-not-exist.txt") is None

    def test_rejects_directory_attachment(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setenv("AUDORA_NOTIFICATION_ALLOWED_ATTACHMENT_DIRS", str(tmp_path))
        assert svc._resolve_safe_attachment_path(str(tmp_path)) is None

    def test_rejects_attachment_outside_allowed_dirs(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "allowed"
        disallowed_dir = tmp_path / "disallowed"
        allowed_dir.mkdir()
        disallowed_dir.mkdir()
        disallowed_file = disallowed_dir / "secret.txt"
        disallowed_file.write_text("sensitive", encoding="utf-8")

        monkeypatch.setenv("AUDORA_NOTIFICATION_ALLOWED_ATTACHMENT_DIRS", str(allowed_dir))
        assert svc._resolve_safe_attachment_path(str(disallowed_file)) is None

    def test_rejects_oversized_attachment(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        large_file = allowed_dir / "large.bin"
        large_file.write_bytes(b"x" * 2048)

        monkeypatch.setenv("AUDORA_NOTIFICATION_ALLOWED_ATTACHMENT_DIRS", str(allowed_dir))
        monkeypatch.setenv("AUDORA_MAX_ATTACHMENT_BYTES", "1024")
        assert svc._resolve_safe_attachment_path(str(large_file)) is None
