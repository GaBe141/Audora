"""Security tests for notification webhook URL validation."""

import json

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

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestNotificationConfigSecurity:
    """Validate notification config persistence and attachment boundaries."""

    def test_save_config_redacts_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.example/secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret-token"

        output_path = tmp_path / "notification_config.json"
        svc.save_config(str(output_path))

        saved = json.loads(output_path.read_text(encoding="utf-8"))
        assert saved["email"]["password"] == "[REDACTED]"
        assert saved["slack"]["webhook_url"] == "[REDACTED]"
        assert saved["webhook"]["headers"]["Authorization"] == "[REDACTED]"

    def test_attachment_must_stay_under_allowed_directory(self, tmp_path, monkeypatch):
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        safe_file = allowed_dir / "report.txt"
        safe_file.write_text("ok", encoding="utf-8")
        unsafe_file = tmp_path / "secret.txt"
        unsafe_file.write_text("secret", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_DIR", str(allowed_dir))

        svc = EnhancedNotificationService()

        assert svc._validated_attachment_path(str(safe_file)) == safe_file.resolve()
        with pytest.raises(ValueError, match="outside the allowed"):
            svc._validated_attachment_path(str(unsafe_file))
