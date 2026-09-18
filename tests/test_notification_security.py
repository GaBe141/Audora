"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message(**kwargs) -> NotificationMessage:
    defaults = {
        "title": "Test alert",
        "content": "<script>alert(1)</script>\nnext line",
        "priority": NotificationPriority.HIGH,
        "channels": [NotificationChannel.CONSOLE],
    }
    defaults.update(kwargs)
    return NotificationMessage(**defaults)


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
    """Outbound webhook POSTs must not follow redirects (SSRF bypass)."""

    def _mock_session(self, status: int = 200):
        response = MagicMock()
        response.status = status
        response.text = AsyncMock(return_value="ok")
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=None)

        session = MagicMock()
        session.post = MagicMock(return_value=response)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        return session, response

    def test_slack_disables_redirects_and_rejects_3xx(self):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        session, _response = self._mock_session(status=302)

        with (
            patch(
                "core.notification_service.socket.getaddrinfo",
                return_value=[(0, 0, 0, "", ("8.8.8.8", 443))],
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_slack(_message()))

        assert session.post.call_args.kwargs.get("allow_redirects") is False
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]

    def test_discord_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        session, _response = self._mock_session(status=204)

        with (
            patch(
                "core.notification_service.socket.getaddrinfo",
                return_value=[(0, 0, 0, "", ("8.8.8.8", 443))],
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_discord(_message()))

        assert session.post.call_args.kwargs.get("allow_redirects") is False
        assert result["success"] is True

    def test_custom_webhook_disables_redirects(self):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        session, _response = self._mock_session(status=201)

        with (
            patch(
                "core.notification_service.socket.getaddrinfo",
                return_value=[(0, 0, 0, "", ("8.8.8.8", 443))],
            ),
            patch("core.notification_service.aiohttp.ClientSession", return_value=session),
        ):
            result = asyncio.run(svc._send_webhook(_message()))

        assert session.post.call_args.kwargs.get("allow_redirects") is False
        assert result["success"] is True


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in plaintext."""

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": False,
        }

        with patch("core.notification_service.smtplib.SMTP") as smtp_cls:
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "TLS" in result["error"]
        smtp_cls.assert_not_called()

    def test_starttls_uses_validated_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        smtp_instance = MagicMock()

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance):
            result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        smtp_instance.starttls.assert_called_once()
        context = smtp_instance.starttls.call_args.kwargs["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        smtp_instance.login.assert_called_once()

    def test_html_email_body_is_escaped(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        captured = {}

        def _send_message(msg: MIMEMultipart):
            captured["msg"] = msg

        smtp_instance = MagicMock()
        smtp_instance.send_message.side_effect = _send_message

        with patch("core.notification_service.smtplib.SMTP", return_value=smtp_instance):
            asyncio.run(svc._send_email(_message()))

        html_part = captured["msg"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part
