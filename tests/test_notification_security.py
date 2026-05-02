"""Security tests for notification hardening."""

import asyncio
import json

import pytest

from core.notification_service import EnhancedNotificationService, NotificationMessage, NotificationPriority


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


class TestNotificationSecretHandling:
    """Validate notification secrets are not persisted or logged unnecessarily."""

    def test_default_webhook_config_does_not_embed_env_token(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_TOKEN", "super-secret")

        svc = EnhancedNotificationService()

        assert "Authorization" not in svc.config["webhook"]["headers"]

    def test_webhook_auth_header_is_built_at_send_time(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_TOKEN", "super-secret")
        svc = EnhancedNotificationService()

        headers = svc._webhook_headers({"X-Custom": "value"})

        assert headers["Authorization"] == "Bearer super-secret"
        assert headers["X-Custom"] == "value"

    def test_save_config_strips_authorization_header(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer should-not-persist"
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert "Authorization" not in saved["webhook"]["headers"]

    def test_response_body_sanitization_bounds_secret_echoes(self):
        svc = EnhancedNotificationService()
        body = "error from https://hooks.slack.com/services/T000/B000/secret\nnext line"

        sanitized = svc._safe_error_body(body, limit=80)

        assert "secret" not in sanitized
        assert "hooks.slack.com/services/[redacted]" in sanitized


class TestEmailSecurity:
    """Validate SMTP delivery refuses plaintext credentials by default."""

    def test_refuses_plaintext_smtp_without_explicit_override(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "use_tls": False,
                "username": "user",
                "password": "password",
                "recipients": ["person@example.com"],
            }
        )
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "Refusing plaintext SMTP" in result["error"]
