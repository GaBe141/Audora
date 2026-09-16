"""Security tests for notification webhook URL validation."""

import asyncio
import inspect
import ssl

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportHardening:
    """Outbound webhook clients must not follow redirects."""

    def test_slack_discord_and_custom_webhooks_disable_redirects(self):
        slack_src = inspect.getsource(EnhancedNotificationService._send_slack)
        discord_src = inspect.getsource(EnhancedNotificationService._send_discord)
        webhook_src = inspect.getsource(EnhancedNotificationService._send_webhook)
        assert "allow_redirects=False" in slack_src
        assert "allow_redirects=False" in discord_src
        assert "allow_redirects=False" in webhook_src
        assert "Redirect responses are not allowed" in slack_src
        assert "Redirect responses are not allowed" in discord_src
        assert "Redirect responses are not allowed" in webhook_src


class TestEmailTransportSecurity:
    """SMTP and HTML email bodies must not leak credentials or inject markup."""

    def test_html_body_escapes_markup(self):
        svc = EnhancedNotificationService()
        body = svc._html_email_body('<script>alert("xss")</script>\nnext')
        assert "<script>" not in body
        assert "&lt;script&gt;" in body
        assert "<br>" in body

    def test_rejects_attachment_outside_export_dir(self, tmp_path, monkeypatch):
        export_root = tmp_path / "exports"
        export_root.mkdir()
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOT", str(export_root))
        svc = EnhancedNotificationService()
        secret = tmp_path / "secret.txt"
        secret.write_text("classified", encoding="utf-8")
        with pytest.raises(ValueError, match="outside the allowed directory"):
            svc._safe_attachment_path(str(secret))

    def test_allows_attachment_inside_export_dir(self, tmp_path, monkeypatch):
        export_root = tmp_path / "exports"
        export_root.mkdir()
        allowed = export_root / "chart.csv"
        allowed.write_text("a,b\n1,2\n", encoding="utf-8")
        monkeypatch.setenv("AUDORA_ATTACHMENT_ROOT", str(export_root))
        svc = EnhancedNotificationService()
        assert svc._safe_attachment_path(str(allowed)) == allowed.resolve()

    def test_refuses_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        captured: dict[str, object] = {}

        class DummySMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, _msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="test",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
