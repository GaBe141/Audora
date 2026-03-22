"""Security tests for notification webhook URL validation."""

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


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


class TestAttachmentSecurity:
    """Validate attachment path restrictions for email notifications."""

    def test_attachment_path_denied_without_allowlist(self, tmp_path):
        attachment = tmp_path / "secret.txt"
        attachment.write_text("classified")

        svc = EnhancedNotificationService()
        assert svc._is_allowed_attachment_path(attachment.resolve()) is False

    def test_attachment_path_allowed_from_configured_directory(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AUDORA_ALLOWED_ATTACHMENT_DIRS", str(tmp_path))
        attachment = tmp_path / "report.txt"
        attachment.write_text("allowed")

        svc = EnhancedNotificationService()
        assert svc._is_allowed_attachment_path(attachment.resolve()) is True

    def test_message_key_is_stable_and_deterministic(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="alert",
            content="same content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )

        assert svc._generate_message_key(message) == svc._generate_message_key(message)
