"""Security tests for notification webhook URL validation."""

import asyncio

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

    def test_post_json_disables_redirects(self, monkeypatch):
        calls = {}

        class FakeResponse:
            status = 302

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def text(self):
                return "redirected"

        class FakeClientSession:
            def __init__(self, *args, **kwargs):
                calls["timeout"] = kwargs.get("timeout")

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def post(self, url, **kwargs):
                calls["url"] = url
                calls["allow_redirects"] = kwargs.get("allow_redirects")
                calls["headers"] = kwargs.get("headers")
                calls["json"] = kwargs.get("json")
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeClientSession)

        svc = EnhancedNotificationService()
        status, body = asyncio.run(
            svc._post_json_no_redirect("https://example.com/hook", {"hello": "world"})
        )

        assert status == 302
        assert body == "redirected"
        assert calls["allow_redirects"] is False
        assert calls["url"] == "https://example.com/hook"
        assert calls["json"] == {"hello": "world"}

    def test_webhook_treats_redirect_as_failure(self, monkeypatch):
        async def fake_post_json_no_redirect(*args, **kwargs):
            return 302, "redirect"

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, allow_private=False: url,
        )
        monkeypatch.setattr(svc, "_post_json_no_redirect", fake_post_json_no_redirect)

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is False
        assert "HTTP 302" in result["error"]

    def test_email_uses_verified_tls_context(self, monkeypatch):
        context_sentinel = object()
        captured = {"tls_context": None, "starttls_called": False}

        class FakeSmtpClient:
            def __init__(self, host, port, timeout=None):
                self.host = host
                self.port = port
                self.timeout = timeout

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def ehlo(self):
                return None

            def starttls(self, context=None):
                captured["starttls_called"] = True
                captured["tls_context"] = context

            def login(self, username, password):
                return None

            def send_message(self, msg):
                return None

        monkeypatch.setattr(
            "core.notification_service.ssl.create_default_context",
            lambda: context_sentinel,
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSmtpClient)

        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        svc.config["email"]["use_tls"] = True

        message = NotificationMessage(
            title="TLS test",
            content="Email body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert captured["starttls_called"] is True
        assert captured["tls_context"] is context_sentinel
