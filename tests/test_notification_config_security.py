"""Security-focused tests for persisted notification configuration."""

import json

from core.notification_service import EnhancedNotificationService


def test_save_config_redacts_secrets(tmp_path):
    """Ensure save_config never writes credential material to disk."""
    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "super-secret"
    svc.config["sms"]["api_key"] = "sms-key"
    svc.config["sms"]["api_secret"] = "sms-secret"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"

    output_file = tmp_path / "notification_config.json"
    svc.save_config(path=str(output_file))

    with output_file.open(encoding="utf-8") as f:
        data = json.load(f)

    assert "password" not in data.get("email", {})
    assert "api_key" not in data.get("sms", {})
    assert "api_secret" not in data.get("sms", {})
    assert "Authorization" not in data.get("webhook", {}).get("headers", {})
