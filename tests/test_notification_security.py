"""Security tests for notification webhook URL validation."""

import hashlib

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


class TestNotificationKeyGeneration:
    """Validate deterministic and stable notification dedupe keys."""

    def test_message_key_is_deterministic(self):
        svc = EnhancedNotificationService()
        key_1 = svc._generate_message_key_payload("same-title", "same-content", "high")
        key_2 = svc._generate_message_key_payload("same-title", "same-content", "high")
        assert key_1 == key_2
        assert len(key_1) == 64  # sha256 hex digest

    def test_message_key_payload_matches_expected_digest(self):
        svc = EnhancedNotificationService()
        expected = hashlib.sha256("title:content:critical".encode("utf-8")).hexdigest()
        assert svc._generate_message_key_payload("title", "content", "critical") == expected
