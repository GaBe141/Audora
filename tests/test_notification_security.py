"""Security tests for notification webhook URL validation."""

import json

import pytest

from core.notification_service import _CONFIG_DIR, EnhancedNotificationService


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

    def test_blocks_loopback_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)

    def test_blocks_ipv4_mapped_loopback_and_metadata(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:169.254.169.254]/latest", allow_private=True)

    def test_blocks_link_local_metadata_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(
                "https://169.254.169.254/latest/meta-data", allow_private=True
            )

    def test_rejects_credentials_and_non_443_ports(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="443"):
            svc._validate_webhook_url("https://example.com:8443/hook")

    def test_smtp_rejects_localhost_and_unexpected_ports(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("localhost", 587)
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("127.0.0.1", 465)
        with pytest.raises(ValueError, match="465 or 587"):
            svc._validate_smtp_target("smtp.example.com", 25)

    def test_save_config_omits_secrets_and_stays_in_config_dir(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_secret"] = "sms-secret"
        path = _CONFIG_DIR / "test_notification_redaction.json"
        try:
            svc.save_config(str(path))
            saved = json.loads(path.read_text(encoding="utf-8"))
            assert "password" not in saved["email"]
            assert "api_secret" not in saved["sms"]
            assert path.stat().st_mode & 0o777 == 0o600
        finally:
            path.unlink(missing_ok=True)

        with pytest.raises(ValueError, match="config directory"):
            svc.save_config("/tmp/notification_config.json")
