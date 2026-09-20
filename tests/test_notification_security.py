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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_strips_crlf_from_headers(self):
        svc = EnhancedNotificationService()
        assert svc._sanitize_header("Subject\r\nBcc: attacker@example.com") == "SubjectBcc: attacker@example.com"

    def test_rejects_attachment_outside_confined_directory(self, tmp_path, monkeypatch):
        attach_dir = tmp_path / "attachments"
        attach_dir.mkdir()
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(attach_dir))
        outside = tmp_path / "secrets.txt"
        outside.write_text("secret", encoding="utf-8")
        svc = EnhancedNotificationService()
        assert svc._resolve_attachment_path(str(outside)) is None

    def test_accepts_attachment_inside_confined_directory(self, tmp_path, monkeypatch):
        attach_dir = tmp_path / "attachments"
        attach_dir.mkdir()
        safe = attach_dir / "report.txt"
        safe.write_text("ok", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(attach_dir))
        svc = EnhancedNotificationService()
        assert svc._resolve_attachment_path(str(safe)) == safe.resolve()
