"""Security tests for notification webhook URL validation."""

import asyncio
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


def _message(**kwargs):
    defaults = {
        "title": "Test",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [NotificationChannel.WEBHOOK],
    }
    defaults.update(kwargs)
    return NotificationMessage(**defaults)


class _FakeResponse:
    def __init__(self, status=200, text="ok"):
        self.status = status
        self._text = text

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, response=None):
        self.response = response or _FakeResponse()
        self.post_kwargs = None
        self.post_url = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, **kwargs):
        self.post_url = url
        self.post_kwargs = kwargs
        return self.response


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


class TestWebhookTransportHardening:
    """Outbound notification HTTP calls must not follow redirects."""

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        fake_session = _FakeSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: fake_session,
        )
        result = asyncio.run(svc._send_webhook(_message()))
        assert fake_session.post_kwargs["allow_redirects"] is False
        assert result["success"] is True

    def test_slack_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        fake_session = _FakeSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: fake_session,
        )
        result = asyncio.run(svc._send_slack(_message(channels=[NotificationChannel.SLACK])))
        assert fake_session.post_kwargs["allow_redirects"] is False
        assert result["success"] is True

    def test_discord_disables_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        fake_session = _FakeSession(response=_FakeResponse(status=204))
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: fake_session,
        )
        result = asyncio.run(svc._send_discord(_message(channels=[NotificationChannel.DISCORD])))
        assert fake_session.post_kwargs["allow_redirects"] is False
        assert result["success"] is True

    def test_rejects_redirect_status(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        fake_session = _FakeSession(response=_FakeResponse(status=302, text="found"))
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: fake_session,
        )
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirects" in result["error"]


class TestEmailTransportSecurity:
    """SMTP must use verified TLS and must not leak files or HTML."""

    def _email_config(self, **overrides):
        config = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        config.update(overrides)
        return config

    def test_rejects_smtp_auth_without_tls(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config(use_tls=False)
        result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        mock_server = MagicMock()
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: mock_server,
        )
        result = asyncio.run(svc._send_email(_message(channels=[NotificationChannel.EMAIL])))
        assert result["success"] is True
        context = mock_server.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_body_escapes_content(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"] = self._email_config()
        mock_server = MagicMock()
        monkeypatch.setattr(
            "core.notification_service.smtplib.SMTP",
            lambda *args, **kwargs: mock_server,
        )
        asyncio.run(
            svc._send_email(
                _message(
                    channels=[NotificationChannel.EMAIL],
                    content="<script>alert(1)</script>",
                )
            )
        )
        sent_msg = mock_server.send_message.call_args[0][0]
        assert isinstance(sent_msg, MIMEMultipart)
        html_bodies = [
            part.get_payload(decode=True).decode("utf-8")
            for part in sent_msg.walk()
            if part.get_content_type() == "text/html"
        ]
        assert html_bodies
        html_body = html_bodies[0]
        assert "&lt;script&gt;" in html_body
        assert "<script>" not in html_body


class TestAttachmentAllowlist:
    """Email attachments must stay inside allowlisted directories."""

    def test_rejects_paths_outside_allowlist(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("password", encoding="utf-8")
        svc = EnhancedNotificationService()
        assert svc._resolve_allowed_attachment(str(secret)) is None

    def test_allows_exports_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        export_dir = tmp_path / "exports"
        export_dir.mkdir()
        chart = export_dir / "chart.csv"
        chart.write_text("a,b\n1,2\n", encoding="utf-8")
        svc = EnhancedNotificationService()
        assert svc._resolve_allowed_attachment(str(chart)) == chart.resolve()
