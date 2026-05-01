"""Security tests for notification transport hardening."""

import asyncio
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

    def test_rejects_private_ip_even_when_env_requests_private_webhooks(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        assert svc._allow_private_webhooks() is False

        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        svc.config["webhook"]["url"] = "https://10.0.0.1/webhook"

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is False
        assert "private or restricted" in result["error"]

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportSecurity:
    """Validate TLS, redirect, and bearer-token protections."""

    def test_default_webhook_headers_omit_empty_authorization(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_TOKEN", raising=False)
        svc = EnhancedNotificationService()
        assert svc.config["webhook"]["headers"] == {"Content-Type": "application/json"}

    def test_save_config_does_not_persist_authorization_header(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WEBHOOK_TOKEN", "super-secret")
        svc = EnhancedNotificationService()
        config_path = tmp_path / "notification_config.json"

        svc.save_config(str(config_path))

        saved = config_path.read_text()
        assert "Authorization" not in saved
        assert "super-secret" not in saved

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured_kwargs = {}

        class FakeResponse:
            status = 302

            async def text(self):
                return "redirect"

        class FakePost:
            async def __aenter__(self):
                return FakeResponse()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakePost()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: FakeSession()
        )
        svc = EnhancedNotificationService()
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, *, allow_private=False: url)
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert captured_kwargs["allow_redirects"] is False
        assert result == {"success": False, "error": "Redirect responses are not allowed"}

    def test_smtp_starttls_uses_validating_ssl_context(self, monkeypatch):
        contexts = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def starttls(self, *, context):
                contexts.append(context)

            def login(self, *_args, **_kwargs):
                pass

            def send_message(self, _msg):
                pass

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert contexts
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED
        assert contexts[0].check_hostname is True

    def test_smtp_auth_requires_tls(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                self.login_called = False

            def login(self, *_args, **_kwargs):
                self.login_called = True

            def quit(self):
                pass

        fake_smtp = FakeSMTP()
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="test",
            content="content",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *_args, **_kwargs: fake_smtp,
        )
        result = asyncio.run(svc._send_email(message))

        assert result == {"success": False, "error": "SMTP authentication requires TLS"}
        assert fake_smtp.login_called is False
