"""Security tests for notification webhook URL validation and delivery hardening."""

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


class TestNotificationTransportHardening:
    """Validate outbound transports keep credentials and webhook targets safe."""

    def test_smtp_starttls_uses_verified_ssl_context(self, monkeypatch):
        sent_messages = []
        smtp_instances = []

        class FakeSMTP:
            def __init__(self, server, port):
                self.server = server
                self.port = port
                self.starttls_context = None
                smtp_instances.append(self)

            def starttls(self, *, context=None):
                self.starttls_context = context

            def login(self, username, password):
                self.username = username
                self.password = password

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                self.quit_called = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Security alert",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert isinstance(smtp_instances[0].starttls_context, ssl.SSLContext)
        assert smtp_instances[0].starttls_context.check_hostname is True
        html_part = sent_messages[0].get_payload()[1]
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_part.get_payload()

    def test_smtp_auth_requires_tls(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, server, port):
                self.quit_called = False

            def quit(self):
                self.quit_called = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["ops@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security alert",
            content="credentials must not cross plaintext SMTP",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]

    def test_webhook_channels_disable_redirects(self, monkeypatch):
        post_calls = []

        class FakeResponse:
            status = 200

            async def text(self):
                return ""

        class FakePostContext:
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
                post_calls.append((url, kwargs))
                return FakePostContext()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)

        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        message = NotificationMessage(
            title="Security alert",
            content="redirects disabled",
            priority=NotificationPriority.CRITICAL,
            channels=[
                NotificationChannel.SLACK,
                NotificationChannel.DISCORD,
                NotificationChannel.WEBHOOK,
            ],
        )

        asyncio.run(svc._send_slack(message))
        asyncio.run(svc._send_discord(message))
        asyncio.run(svc._send_webhook(message))

        assert len(post_calls) == 3
        assert all(kwargs["allow_redirects"] is False for _, kwargs in post_calls)
