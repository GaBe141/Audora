"""Security-focused tests for notification URL validation and config persistence."""

import json

from core.notification_service import EnhancedNotificationService, validate_outbound_webhook_url


def test_validate_outbound_webhook_url_rejects_http():
    is_safe, reason = validate_outbound_webhook_url("http://example.com/webhook")
    assert is_safe is False
    assert "HTTPS" in reason


def test_validate_outbound_webhook_url_rejects_localhost():
    is_safe, reason = validate_outbound_webhook_url("https://localhost/webhook")
    assert is_safe is False
    assert "Localhost" in reason


def test_validate_outbound_webhook_url_rejects_private_ip():
    is_safe, reason = validate_outbound_webhook_url("https://10.10.10.10/hook")
    assert is_safe is False
    assert "Non-public IP" in reason


def test_validate_outbound_webhook_url_accepts_public_ip_literal():
    is_safe, reason = validate_outbound_webhook_url("https://1.1.1.1/hook")
    assert is_safe is True
    assert reason == ""


def test_save_config_redacts_sensitive_fields(tmp_path):
    service = EnhancedNotificationService()
    service.config["email"]["password"] = "super-secret"
    service.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/TOKEN"
    service.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/xyz"
    service.config["webhook"]["url"] = "https://example.com/hook"
    service.config["webhook"]["headers"]["Authorization"] = "Bearer secret-token"
    service.config["sms"]["api_key"] = "sms-key"
    service.config["sms"]["api_secret"] = "sms-secret"

    output_path = tmp_path / "notification_config.json"
    service.save_config(str(output_path))

    persisted = json.loads(output_path.read_text(encoding="utf-8"))
    assert "password" not in persisted["email"]
    assert "webhook_url" not in persisted["slack"]
    assert "webhook_url" not in persisted["discord"]
    assert "url" not in persisted["webhook"]
    assert "Authorization" not in persisted["webhook"]["headers"]
    assert "api_key" not in persisted["sms"]
    assert "api_secret" not in persisted["sms"]
