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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_shared_address_space_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")


class TestWebhookDeliverySecurity:
    """Validate outbound webhook delivery options."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured_kwargs = {}

        class FakeResponse:
            status = 302

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            def post(self, _url, **kwargs):
                captured_kwargs.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(
            svc,
            "_validate_webhook_url",
            lambda url, *, allow_private=False: url,
        )

        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert captured_kwargs["allow_redirects"] is False
        assert result == {"success": False, "error": "HTTP 302"}


class TestEmailDeliverySecurity:
    """Validate SMTP and email body hardening."""

    def test_refuses_smtp_authentication_without_tls(self, monkeypatch):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("SMTP should not be opened when auth would be plaintext")

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fail_if_called)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="content",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result == {"success": False, "error": "Refusing SMTP authentication without TLS"}

    def test_escapes_html_email_body(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                pass

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "",
                "password": "",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Test",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        html_part = sent_messages[0].get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode()
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_body
        assert "<script>" not in html_body
