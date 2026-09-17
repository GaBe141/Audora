"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import inspect
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="<script>alert(1)</script>\nnext line",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_cgnat_and_ipv4_mapped_private_addresses(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        assert svc._is_restricted_ip("::ffff:10.0.0.1") is True
        assert svc._is_restricted_ip("8.8.8.8") is False
        assert svc._is_restricted_ip("::ffff:8.8.8.8") is False


class TestWebhookTransportHardening:
    """Outbound webhook POSTs must not follow redirects."""

    def test_channel_sends_disable_redirects(self):
        slack_src = inspect.getsource(EnhancedNotificationService._send_slack)
        discord_src = inspect.getsource(EnhancedNotificationService._send_discord)
        webhook_src = inspect.getsource(EnhancedNotificationService._send_webhook)
        assert "allow_redirects=False" in slack_src
        assert "allow_redirects=False" in discord_src
        assert "allow_redirects=False" in webhook_src
        assert "Redirect responses are not allowed" in slack_src
        assert "Redirect responses are not allowed" in discord_src
        assert "Redirect responses are not allowed" in webhook_src


class TestSmtpTransportHardening:
    """SMTP auth must not run over plaintext and STARTTLS must validate certs."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["a@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_validated_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "alerts@example.com",
            "recipients": ["a@example.com"],
            "use_tls": True,
        }

        fake_server = MagicMock()
        captured: dict[str, object] = {}

        def _smtp(*_args, **_kwargs):
            return fake_server

        def _starttls(*, context=None):
            captured["context"] = context

        fake_server.starttls.side_effect = _starttls
        monkeypatch.setattr("smtplib.SMTP", _smtp)

        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        fake_server.login.assert_called_once_with("user", "pass")

        sent_msg = fake_server.send_message.call_args[0][0]
        assert isinstance(sent_msg, MIMEMultipart)
        html_part = sent_msg.get_payload()[1]
        html_body = html_part.get_payload(decode=True).decode("utf-8")
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body
