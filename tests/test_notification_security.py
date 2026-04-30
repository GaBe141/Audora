"""Security tests for notification webhook URL validation."""

import pytest
from jinja2.sandbox import SandboxedEnvironment

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


class TestNotificationTemplateSecurity:
    """Validate safe template rendering for notification content."""

    def test_template_environment_is_sandboxed(self):
        svc = EnhancedNotificationService()
        assert isinstance(svc.template_env, SandboxedEnvironment)

    def test_template_context_converts_objects_to_inert_strings(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Test",
            content="Fallback",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.CONSOLE],
            template_vars={
                "template": "viral_prediction",
                "track_name": object(),
                "artist": "Artist",
                "viral_probability": 90,
                "confidence": 80,
                "predicted_peak_date": "tomorrow",
                "key_factors": [],
                "risk_factors": [],
            },
        )

        rendered = svc._render_template(message)

        assert "Artist" in rendered
        assert "object at" not in rendered

    def test_unknown_template_is_rejected(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Test",
            content="Fallback",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.CONSOLE],
            template_vars={"template": "../private"},
        )

        with pytest.raises(ValueError, match="Unknown notification template"):
            svc._render_template(message)
