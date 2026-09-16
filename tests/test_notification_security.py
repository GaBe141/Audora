"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _test_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="payload",
        priority=NotificationPriority.LOW,
        channels=[channel],
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


class _AsyncCM:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status

    async def text(self) -> str:
        return "redirected"


class _FakeSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.post_calls: list[dict] = []

    def post(self, url, **kwargs):
        self.post_calls.append({"url": url, **kwargs})
        return _AsyncCM(_FakeResponse(self.status))


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects to unvalidated hosts."""

    def test_custom_webhook_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/webhook"
        svc.config["webhook"]["headers"] = {"Content-Type": "application/json"}
        session = _FakeSession(status=302)

        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=_AsyncCM(session)),
        ):
            result = asyncio.run(svc._send_webhook(_test_message(NotificationChannel.WEBHOOK)))

        assert result["success"] is False
        assert "redirect" in result["error"].lower()
        assert session.post_calls[0]["allow_redirects"] is False

    def test_slack_and_discord_disable_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"

        for send, channel, config_key in (
            (svc._send_slack, NotificationChannel.SLACK, "slack"),
            (svc._send_discord, NotificationChannel.DISCORD, "discord"),
        ):
            session = _FakeSession(status=200)
            with (
                patch.object(
                    svc,
                    "_validate_webhook_url",
                    return_value=svc.config[config_key]["webhook_url"],
                ),
                patch(
                    "core.notification_service.aiohttp.ClientSession",
                    return_value=_AsyncCM(session),
                ),
            ):
                result = asyncio.run(send(_test_message(channel)))

            assert result["success"] is True
            assert session.post_calls[0]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP credentials must only be sent over verified TLS."""

    def test_refuses_plaintext_smtp_authentication(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "notifier",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }

        with patch("core.notification_service.smtplib.SMTP") as smtp_cls:
            result = asyncio.run(svc._send_email(_test_message(NotificationChannel.EMAIL)))

        assert result["success"] is False
        assert "TLS" in result["error"]
        smtp_cls.assert_not_called()

    def test_starttls_uses_default_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "notifier",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=server) as smtp_cls:
            result = asyncio.run(svc._send_email(_test_message(NotificationChannel.EMAIL)))

        assert result["success"] is True
        smtp_cls.assert_called_once()
        context = server.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        server.login.assert_called_once_with("notifier", "secret")
