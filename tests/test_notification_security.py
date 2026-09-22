"""Security tests for notification webhook URL validation."""

import socket

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

    def test_rejects_loopback_even_when_private_webhooks_are_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/webhook", allow_private=True)

    def test_rejects_link_local_metadata_address(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest/", allow_private=True)

    def test_rejects_credentials_obfuscation_mapped_and_local_suffixes(self):
        svc = EnhancedNotificationService()
        rejected = [
            "https://user:pass@example.com/hook",
            "https://2130706433/hook",
            "https://0177.0.0.1/hook",
            "https://[::ffff:10.0.0.1]/hook",
            "https://evil.localhost/hook",
            "https://metadata.google.internal/computeMetadata/v1/",
        ]
        for url in rejected:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_rejects_hostname_that_resolves_to_loopback(self, monkeypatch):
        def fake_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/hook", allow_private=True)

    def test_rejects_config_path_outside_config_directory(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config"):
            svc.save_config("/tmp/notification_config.json")
