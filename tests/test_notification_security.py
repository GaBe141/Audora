"""Security tests for notification webhook URL validation."""

import json
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

    def test_rejects_loopback_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)

    def test_rejects_ipv4_mapped_loopback_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)

    def test_rejects_link_local_metadata_address_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_rejects_non_standard_port(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="port 443"):
            svc._validate_webhook_url("https://example.com:8443/webhook")

    def test_rejects_userinfo(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_smtp_rejects_localhost_and_non_mail_ports(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("localhost", 587)
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_target("127.0.0.1", 465)
        with pytest.raises(ValueError, match="465 or 587"):
            svc._validate_smtp_target("smtp.example.com", 25)

    def test_save_config_omits_secrets_and_stays_in_config_dir(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        target = Path("config/pytest_notification_security.json")
        try:
            svc.save_config(str(target))
            saved = json.loads(target.read_text(encoding="utf-8"))
            assert "password" not in saved["email"]
            assert "api_key" not in saved["sms"]
            assert "Authorization" not in saved["webhook"].get("headers", {})
            assert target.stat().st_mode & 0o777 == 0o600
        finally:
            target.unlink(missing_ok=True)

        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(tmp_path / "notification_config.json"))
