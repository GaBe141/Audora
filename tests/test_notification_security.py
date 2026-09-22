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

    def test_rejects_credentials_in_webhook_url(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_obfuscated_loopback_literals(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://2130706433/webhook",
            "https://0x7f000001/webhook",
            "https://0177.0.0.1/webhook",
            "https://[::ffff:127.0.0.1]/webhook",
        ):
            with pytest.raises(ValueError, match="Localhost|link-local"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_rejects_link_local_metadata_even_when_private_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="link-local"):
            svc._validate_webhook_url(
                "https://169.254.169.254/latest/meta-data", allow_private=True
            )

    def test_rejects_metadata_hostname_without_dns(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="not allowed"):
            svc._validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_rejects_private_address_hidden_behind_public_dns(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (None, None, None, "", ("1.2.3.4", port)),
                (None, None, None, "", ("10.1.2.3", port)),
            ]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://music.example/hook")
