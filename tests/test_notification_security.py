"""Security tests for notification delivery and configuration."""

import asyncio
import json

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


class TestNotificationConfigPersistence:
    """Ensure saved config does not leak sensitive tokens."""

    def test_save_config_omits_secrets(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "smtp-secret"
        svc.config["webhook"]["headers"]["Authorization"] = "Bearer webhook-secret"
        svc.config["sms"]["api_key"] = "sms-key"
        svc.config["sms"]["api_secret"] = "sms-secret"

        config_path = tmp_path / "notification_config.json"
        svc.save_config(str(config_path))

        saved = json.loads(config_path.read_text())
        assert saved["email"].get("password") is None
        assert saved["webhook"]["headers"].get("Authorization") is None
        assert saved["sms"].get("api_key") is None
        assert saved["sms"].get("api_secret") is None
        assert "smtp-secret" not in config_path.read_text()
        assert "webhook-secret" not in config_path.read_text()


class TestEmailTransportSecurity:
    """Validate TLS setup for SMTP transports."""

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["to@example.com"],
                "use_tls": True,
            }
        )
        context = object()
        calls = {}

        class FakeSMTP:
            def __init__(self, host, port):
                calls["smtp"] = (host, port)

            def starttls(self, *, context):
                calls["starttls_context"] = context

            def login(self, username, password):
                calls["login"] = (username, password)

            def send_message(self, msg):
                calls["sent"] = msg["Subject"]

            def quit(self):
                calls["quit"] = True

        monkeypatch.setattr("core.notification_service.ssl.create_default_context", lambda: context)
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Subject",
                    content="Body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        assert calls["smtp"] == ("smtp.example.com", 587)
        assert calls["starttls_context"] is context
        assert calls["login"] == ("user", "pass")
        assert calls["quit"] is True

    def test_smtp_ssl_used_for_implicit_tls_port(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 465,
                "recipients": ["to@example.com"],
                "use_tls": True,
            }
        )
        context = object()
        calls = {}

        class FakeSMTPSSL:
            def __init__(self, host, port, *, context):
                calls["smtp_ssl"] = (host, port)
                calls["context"] = context

            def send_message(self, msg):
                calls["sent"] = msg["Subject"]

            def quit(self):
                calls["quit"] = True

        monkeypatch.setattr("core.notification_service.ssl.create_default_context", lambda: context)
        monkeypatch.setattr("core.notification_service.smtplib.SMTP_SSL", FakeSMTPSSL)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="Subject",
                    content="Body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        assert calls["smtp_ssl"] == ("smtp.example.com", 465)
        assert calls["context"] is context
        assert calls["quit"] is True
