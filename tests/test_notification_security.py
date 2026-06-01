"""Security tests for notification webhook URL validation."""

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

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportSecurity:
    """Validate notification transports avoid insecure redirects and plaintext auth."""

    def _message(self) -> NotificationMessage:
        return NotificationMessage(
            title="Security test",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

    def test_email_starttls_uses_validating_ssl_context_and_escapes_html(self, monkeypatch):
        smtp_instances = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                self.starttls_context = None
                self.sent_message = None
                self.quit_called = False
                smtp_instances.append(self)

            def starttls(self, *, context=None):
                self.starttls_context = context

            def login(self, *_args):
                return None

            def send_message(self, message):
                self.sent_message = message

            def quit(self):
                self.quit_called = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        smtp = smtp_instances[0]
        html_body = smtp.sent_message.get_payload()[1].get_payload()
        assert result["success"] is True
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.check_hostname is True
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body
        assert smtp.quit_called is True

    def test_email_refuses_plaintext_smtp_auth(self, monkeypatch):
        smtp_instances = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs):
                self.login_called = False
                self.quit_called = False
                smtp_instances.append(self)

            def login(self, *_args):
                self.login_called = True

            def send_message(self, _message):
                return None

            def quit(self):
                self.quit_called = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(self._message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert smtp_instances[0].login_called is False
        assert smtp_instances[0].quit_called is True

    def test_custom_webhook_disables_redirects_and_sets_timeout(self, monkeypatch):
        calls = []

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def text(self):
                return ""

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def post(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc.config["webhook"].update({"url": "https://example.com/webhook", "timeout": 7})

        result = asyncio.run(svc._send_webhook(self._message()))

        assert result["success"] is True
        assert calls[0][1]["allow_redirects"] is False
        assert calls[0][1]["timeout"].total == 7
