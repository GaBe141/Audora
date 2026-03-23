"""Security tests for notification webhook URL validation."""

from pathlib import Path

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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_disallowed_non_standard_port(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="disallowed port"):
            svc._validate_webhook_url("https://10.0.0.1:8443/webhook", allow_private=True)

    def test_accepts_allowed_port_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_ALLOWED_WEBHOOK_PORTS", "443,8443")
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1:8443/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestAttachmentPathValidation:
    """Validate attachment path restrictions for notifications."""

    def test_rejects_attachment_outside_allowed_roots(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", raising=False)
        svc = EnhancedNotificationService()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret", encoding="utf-8")

        with pytest.raises(ValueError, match="outside allowed directories"):
            svc._resolve_safe_attachment_path(str(outside_file))

    def test_allows_attachment_from_explicit_allowlist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", str(tmp_path))
        svc = EnhancedNotificationService()
        allowed_file = tmp_path / "report.txt"
        allowed_file.write_text("ok", encoding="utf-8")

        resolved = svc._resolve_safe_attachment_path(str(allowed_file))
        assert resolved == allowed_file.resolve()
