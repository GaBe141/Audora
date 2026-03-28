"""Security tests for notification webhook URL validation."""

import pytest
import re

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
    """Ensure message keys are stable and hash-randomization safe."""

    def test_message_key_is_sha256_hex(self):
        svc = EnhancedNotificationService()
        message = type(
            "Msg",
            (),
            {
                "title": "High Viral Potential",
                "content": "Track growth accelerated by 350%",
                "priority": type("Prio", (), {"value": "critical"})(),
            },
        )()
        msg = svc._generate_message_key(message)
        assert re.fullmatch(r"[0-9a-f]{64}:critical", msg) is not None
