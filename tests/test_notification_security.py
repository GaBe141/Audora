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
        assert svc._validate_webhook_url(url, allow_private=True).url == url

    def test_rejects_credentials_in_webhook_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_decimal_and_hex_ip_literals(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://2130706433/webhook",
            "https://0x7f000001/webhook",
            "https://127.1/webhook",
        ):
            with pytest.raises(ValueError, match="Obfuscated"):
                svc._validate_webhook_url(url)

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/webhook")

    def test_rejects_localhost_suffix(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://evil.localhost/webhook")

    def test_save_config_rejects_path_escape(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config("/tmp/notification_config.json")

    def test_attachment_path_rejects_escape(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        with pytest.raises(ValueError, match="data directory"):
            svc._resolve_attachment_path(str(outside))
