"""Security tests for outbound notification behavior."""

import string

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestWebhookUrlValidation:
    """Validate webhook URL hardening against insecure targets."""

    def test_rejects_non_https_webhook_url(self):
        svc = EnhancedNotificationService()
        is_valid, error = svc._validate_outbound_webhook_url("http://example.com/hook")
        assert is_valid is False
        assert error is not None
        assert "HTTPS" in error

    def test_rejects_localhost_and_private_ip_targets(self):
        svc = EnhancedNotificationService()

        localhost_valid, _ = svc._validate_outbound_webhook_url("https://localhost/hook")
        private_ip_valid, _ = svc._validate_outbound_webhook_url("https://127.0.0.1/hook")

        assert localhost_valid is False
        assert private_ip_valid is False

    def test_accepts_valid_public_https_url(self):
        svc = EnhancedNotificationService()
        is_valid, error = svc._validate_outbound_webhook_url("https://example.com/hook")
        assert is_valid is True
        assert error is None

    def test_enforces_allowed_host_allowlist(self):
        svc = EnhancedNotificationService()

        slack_valid, _ = svc._validate_outbound_webhook_url(
            "https://hooks.slack.com/services/T000/B000/XXX",
            allowed_hosts={"hooks.slack.com"},
        )
        evil_valid, _ = svc._validate_outbound_webhook_url(
            "https://evil.example.com/hook",
            allowed_hosts={"hooks.slack.com"},
        )

        assert slack_valid is True
        assert evil_valid is False


class TestNotificationKeySecurity:
    """Validate deterministic cryptographic message keys."""

    def test_generate_message_key_is_sha256_hex(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Critical alert",
            content="Something important happened",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.CONSOLE],
        )

        key = svc._generate_message_key(message)
        assert len(key) == 64
        assert all(ch in string.hexdigits for ch in key)


def test_save_config_rejects_insecure_custom_webhook(tmp_path):
    svc = EnhancedNotificationService()
    svc.config["webhook"]["url"] = "http://localhost:8080/hook"

    with pytest.raises(ValueError, match="Invalid custom webhook URL"):
        svc.save_config(str(tmp_path / "notification_config.json"))
