"""Security tests for notification webhook URL validation."""

import asyncio
import inspect
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


def _email_message(title: str = "Test", content: str = "hello") -> NotificationMessage:
    return NotificationMessage(
        title=title,
        content=content,
        priority=NotificationPriority.LOW,
        channels=[],
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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestNotificationTransportHardening:
    """SMTP TLS and webhook redirect/SSRF transport guards."""

    def test_webhook_posts_disable_redirects(self):
        source = inspect.getsource(EnhancedNotificationService._send_webhook)
        source += inspect.getsource(EnhancedNotificationService._send_slack)
        source += inspect.getsource(EnhancedNotificationService._send_discord)
        assert source.count("allow_redirects=False") >= 3
        assert "Webhook redirect responses are not allowed" in source

    def test_smtp_auth_requires_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_email_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        mock_server = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=mock_server):
            result = asyncio.run(svc._send_email(_email_message(content="<script>alert(1)</script>")))
        assert result["success"] is True
        mock_server.starttls.assert_called_once()
        context = mock_server.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        sent_msg = mock_server.send_message.call_args[0][0]
        assert isinstance(sent_msg, MIMEMultipart)
        raw = sent_msg.as_string()
        html_part = raw.split("text/html", 1)[-1]
        assert "&lt;script&gt;" in html_part
        assert "<script>" not in html_part

    def test_email_headers_strip_crlf(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": True,
        }
        mock_server = MagicMock()
        injected = "Subject\r\nBcc: attacker@example.com"
        with patch("core.notification_service.smtplib.SMTP", return_value=mock_server):
            result = asyncio.run(svc._send_email(_email_message(title=injected)))
        assert result["success"] is True
        sent_msg = mock_server.send_message.call_args[0][0]
        assert "\r" not in sent_msg["Subject"]
        assert "\n" not in sent_msg["Subject"]
        assert sent_msg["Subject"].count(":") <= 1
