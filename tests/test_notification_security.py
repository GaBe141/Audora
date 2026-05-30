"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import patch

import pytest

import core.notification_service as notification_service
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


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    instances = []
    post_calls = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append({"args": args, "kwargs": kwargs})
        return _FakeResponse()


class TestWebhookTransportSecurity:
    """Validate transport-level protections for outbound webhooks."""

    def setup_method(self):
        _FakeSession.instances = []
        _FakeSession.post_calls = []

    @patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch.object(notification_service.aiohttp, "ClientSession", _FakeSession)
    def test_slack_webhook_disables_redirects_and_sets_timeout(self, _mock_getaddrinfo):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakeSession.instances[0].kwargs["timeout"].total == 10
        assert _FakeSession.post_calls[0]["kwargs"]["allow_redirects"] is False

    @patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch.object(notification_service.aiohttp, "ClientSession", _FakeSession)
    def test_custom_webhook_disables_redirects(self, _mock_getaddrinfo):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom"
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeSession.post_calls[0]["kwargs"]["allow_redirects"] is False


class TestEmailTransportSecurity:
    """Validate SMTP credential and HTML transport protections."""

    def test_starttls_uses_default_verifying_ssl_context(self):
        created_servers = []

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                self.started_context = None
                self.sent_message = None
                created_servers.append(self)

            def starttls(self, *, context=None):
                self.started_context = context

            def login(self, username, password):
                return None

            def send_message(self, message):
                self.sent_message = message

            def quit(self):
                return None

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        message = NotificationMessage(
            title="Title",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.EMAIL],
        )

        with patch.object(notification_service.smtplib, "SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context = created_servers[0].started_context
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

        html_part = created_servers[0].sent_message.get_payload()[1]
        html_payload = html_part.get_payload(decode=True).decode()
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_payload

    def test_refuses_plaintext_smtp_authentication(self):
        class FakeSMTP:
            def starttls(self, *, context=None):
                raise AssertionError("STARTTLS should not be called")

            def login(self, username, password):
                raise AssertionError("login should not be called without TLS")

            def send_message(self, message):
                raise AssertionError("message should not be sent")

            def quit(self):
                return None

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["user@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Title",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch.object(notification_service.smtplib, "SMTP", lambda *args, **kwargs: FakeSMTP()):
            result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "requires TLS" in result["error"]
