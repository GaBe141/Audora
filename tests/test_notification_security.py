"""Security tests for notification webhook URL validation and delivery hardening."""

import smtplib
from contextlib import nullcontext
from email import message_from_string
from unittest.mock import AsyncMock, Mock, patch

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


class MockAioHttpResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._body


class MockAioHttpSession:
    last_post_kwargs = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        type(self).last_post_kwargs = kwargs
        return MockAioHttpResponse()


class TestNotificationTransportHardening:
    """Validate secure transport options for outbound notifications."""

    @pytest.mark.parametrize(
        ("method_name", "config"),
        [
            ("_send_slack", {"slack": {"webhook_url": "https://example.com/slack"}}),
            ("_send_discord", {"discord": {"webhook_url": "https://example.com/discord"}}),
            ("_send_webhook", {"webhook": {"url": "https://example.com/webhook"}}),
        ],
    )
    @pytest.mark.asyncio
    async def test_webhook_channels_disable_redirects(self, method_name, config):
        svc = EnhancedNotificationService()
        svc.config.update(config)
        message = NotificationMessage(
            title="alert",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        with (
            patch.object(svc, "_validate_webhook_url", side_effect=lambda url, **_: url),
            patch("core.notification_service.aiohttp.ClientSession", MockAioHttpSession),
        ):
            result = await getattr(svc, method_name)(message)

        assert result["success"] is True
        assert MockAioHttpSession.last_post_kwargs["allow_redirects"] is False

    @pytest.mark.asyncio
    async def test_email_starttls_uses_verified_ssl_context(self):
        smtp = Mock()
        smtp.starttls = Mock()
        smtp.login = Mock()
        smtp.send_message = Mock()
        smtp.quit = Mock()

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "recipients": ["ops@example.com"],
            "from_address": "alerts@example.com",
            "use_tls": True,
        }
        message = NotificationMessage(
            title="alert",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        context = smtp.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode.name == "CERT_REQUIRED"
        smtp.login.assert_called_once_with("user", "pass")

    @pytest.mark.asyncio
    async def test_email_refuses_plaintext_smtp_auth(self):
        smtp = Mock()
        smtp.quit = Mock()

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "recipients": ["ops@example.com"],
            "from_address": "alerts@example.com",
            "use_tls": False,
        }
        message = NotificationMessage(
            title="alert",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is False
        assert "without TLS" in result["error"]
        smtp.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_email_html_body_escapes_message_content(self):
        sent_message = None

        def capture_message(msg):
            nonlocal sent_message
            sent_message = msg

        smtp = Mock()
        smtp.starttls = Mock()
        smtp.send_message = Mock(side_effect=capture_message)
        smtp.quit = Mock()

        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "recipients": ["ops@example.com"],
            "from_address": "alerts@example.com",
            "use_tls": True,
        }
        message = NotificationMessage(
            title="alert",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = await svc._send_email(message)

        assert result["success"] is True
        html_part = sent_message.get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode()
        assert "<script>" not in html_body
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body
