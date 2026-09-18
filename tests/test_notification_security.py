"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**overrides) -> NotificationMessage:
    defaults = {
        "title": "Test alert",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.WEBHOOK],
    }
    defaults.update(overrides)
    return NotificationMessage(**defaults)


class FakeResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class FakeSession:
    def __init__(self, status: int = 200):
        self.post_calls: list[tuple[str, dict]] = []
        self._status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return FakeResponse(status=self._status)


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


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects (SSRF bypass)."""

    def test_slack_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/T/B/X"
        fake_session = FakeSession()
        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["slack"]["webhook_url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_slack(_message(channels=[NotificationChannel.SLACK])))
        assert result["success"] is True
        assert fake_session.post_calls
        assert fake_session.post_calls[0][1].get("allow_redirects") is False

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/1/2"
        fake_session = FakeSession(status=204)
        with (
            patch.object(
                svc, "_validate_webhook_url", return_value=svc.config["discord"]["webhook_url"]
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(
                svc._send_discord(_message(channels=[NotificationChannel.DISCORD]))
            )
        assert result["success"] is True
        assert fake_session.post_calls[0][1].get("allow_redirects") is False

    def test_custom_webhook_rejects_redirect_status(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        fake_session = FakeSession(status=302)
        with (
            patch.object(svc, "_validate_webhook_url", return_value=svc.config["webhook"]["url"]),
            patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
        ):
            result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirects are not allowed" in result["error"]
        assert fake_session.post_calls[0][1].get("allow_redirects") is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS before authenticating."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        mock_server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=mock_server):
            result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is True
        mock_server.starttls.assert_called_once()
        context = mock_server.starttls.call_args.kwargs.get("context")
        if context is None and mock_server.starttls.call_args.args:
            context = mock_server.starttls.call_args.args[0]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        mock_server.login.assert_called_once()

    def test_email_html_escapes_content_and_strips_headers(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com\nBcc: evil@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        captured: dict[str, MIMEMultipart] = {}

        def _send_message(msg):
            captured["msg"] = msg

        mock_server = MagicMock()
        mock_server.send_message.side_effect = _send_message
        with patch("core.notification_service.smtplib.SMTP", return_value=mock_server):
            result = asyncio.run(
                svc._send_email(
                    _message(
                        title="Alert\nX-Injected: 1",
                        content="<script>alert(1)</script>",
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )
        assert result["success"] is True
        msg = captured["msg"]
        assert "\n" not in msg["Subject"]
        assert "\n" not in msg["From"]
        html_part = next(
            part.get_payload() for part in msg.walk() if part.get_content_type() == "text/html"
        )
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
