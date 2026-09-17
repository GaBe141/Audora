"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart

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
        content="<script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
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

    def test_rejects_cgnat_ip_targets(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.1.8/webhook")

    def test_rejects_ipv4_mapped_private_targets(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:10.0.0.1") is True
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:10.0.0.1]/webhook")

    def test_allows_public_ip(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("8.8.8.8") is False

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransportHardening:
    """Outbound Slack/Discord/custom webhooks must not follow redirects."""

    def _patch_session(self, monkeypatch, status: int = 200):
        captured: dict[str, object] = {}

        class FakeResponse:
            def __init__(self) -> None:
                self.status = status

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb) -> bool:
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr("aiohttp.ClientSession", FakeSession)
        return captured

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)
        captured = self._patch_session(monkeypatch)

        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)
        captured = self._patch_session(monkeypatch)

        result = asyncio.run(svc._send_slack(_message()))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)
        captured = self._patch_session(monkeypatch, status=204)

        result = asyncio.run(svc._send_discord(_message()))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False

    def test_webhook_rejects_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, **kwargs: url)
        self._patch_session(monkeypatch, status=302)

        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]


class TestSmtpTransportHardening:
    """SMTP credentials must only be sent after verified TLS."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "alerts@example.com",
            "recipients": ["ops@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
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
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def starttls(self, context=None) -> None:
                captured["context"] = context

            def login(self, username, password) -> None:
                captured["login"] = (username, password)

            def send_message(self, msg) -> None:
                captured["message"] = msg

            def quit(self) -> None:
                captured["quit"] = True

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        message = captured["message"]
        assert isinstance(message, MIMEMultipart)
        html_part = message.get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "alert(1)" in html_part
