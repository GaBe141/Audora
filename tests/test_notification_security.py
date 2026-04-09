"""Security tests for notification webhook URL validation."""

import json

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationConfigAndDedup:
    """Security tests for persisted config and dedupe key stability."""

    def test_save_config_masks_authorization_header(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer top-secret-token"
        target = tmp_path / "notification_config.json"

        svc.save_config(str(target))
        saved = json.loads(target.read_text(encoding="utf-8"))

        assert saved["webhook"]["headers"]["Authorization"] == "Bearer ${WEBHOOK_TOKEN}"

    def test_generate_message_key_is_stable_for_equivalent_messages(self):
        svc = EnhancedNotificationService()

        from core.notification_service import (
            NotificationChannel,
            NotificationMessage,
            NotificationPriority,
        )

        msg_a = NotificationMessage(
            title="Hello",
            content="World",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK, NotificationChannel.DISCORD],
            data={"b": 2, "a": 1},
        )
        msg_b = NotificationMessage(
            title="Hello",
            content="World",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.DISCORD, NotificationChannel.SLACK],
            data={"a": 1, "b": 2},
        )

        assert svc._generate_message_key(msg_a) == svc._generate_message_key(msg_b)
