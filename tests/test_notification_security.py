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

    def test_blocks_loopback_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)

    def test_blocks_ipv4_mapped_private_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.0.0.1]/hook", allow_private=True)

    def test_rejects_userinfo_and_non_standard_port(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user@example.com/hook")
        with pytest.raises(ValueError, match="port 443"):
            svc._validate_webhook_url("https://example.com:8443/hook")

    def test_rejects_localhost_smtp(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("localhost", 587)

    def test_saved_config_omits_secrets(self):
        svc = EnhancedNotificationService()
        config_dir = svc._config_directory()
        config_dir.mkdir(parents=True, exist_ok=True)
        target = config_dir / "notification_config_security_test.json"
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_key"] = "sms-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        try:
            svc.save_config(str(target))
            saved = target.read_text(encoding="utf-8")
            assert "super-secret" not in saved
            assert "sms-secret" not in saved
            assert "Bearer secret" not in saved
            assert oct(target.stat().st_mode & 0o777) == "0o600"
        finally:
            target.unlink(missing_ok=True)

    def test_saved_config_cannot_escape_config_directory(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config("config/../notification_config.json")
