"""Security tests for notification webhook URL validation."""

import socket
from unittest.mock import patch

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

    def test_rejects_credentials_and_obfuscated_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://2130706433/webhook")
        with pytest.raises(ValueError, match="IPv4-mapped"):
            svc._validate_webhook_url("https://[::ffff:8.8.8.8]/webhook")
        with pytest.raises(ValueError, match="metadata"):
            svc._validate_webhook_url("https://metadata.google.internal/webhook")

    def test_allows_public_hostname_when_resolution_is_public(self):
        svc = EnhancedNotificationService()
        url = "https://hooks.slack.com/services/T00/B00/secret"
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]
        with patch("core.notification_service.socket.getaddrinfo", return_value=public):
            assert svc._validate_webhook_url(url, allow_private=False) == url
