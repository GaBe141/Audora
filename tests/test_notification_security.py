"""Security tests for notification webhook URL validation."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart
from unittest.mock import patch

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
        content="hello <script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
    )


class DummyResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def text(self) -> str:
        return "ok"

    async def __aenter__(self) -> "DummyResponse":
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False


class DummySession:
    def __init__(self) -> None:
        self.post_kwargs: dict = {}

    async def __aenter__(self) -> "DummySession":
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    def post(self, url: str, **kwargs: object) -> DummyResponse:
        self.post_kwargs = {"url": url, **kwargs}
        return DummyResponse(status=200)


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
    """Outbound webhook posts must not follow redirects."""

    def test_slack_disables_redirects(self, monkeypatch):
        session = DummySession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: session
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/slack"
        result = asyncio.run(svc._send_slack(_message()))
        assert result["success"] is True
        assert session.post_kwargs.get("allow_redirects") is False

    def test_discord_disables_redirects(self, monkeypatch):
        session = DummySession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: session
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        result = asyncio.run(svc._send_discord(_message()))
        assert result["success"] is True
        assert session.post_kwargs.get("allow_redirects") is False

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        session = DummySession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: session
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert session.post_kwargs.get("allow_redirects") is False

    def test_webhook_rejects_redirect_status(self, monkeypatch):
        class RedirectSession(DummySession):
            def post(self, url: str, **kwargs: object) -> DummyResponse:
                self.post_kwargs = {"url": url, **kwargs}
                return DummyResponse(status=302)

        session = RedirectSession()
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession", lambda: session
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "redirect" in result["error"].lower()


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in plaintext."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "secret"
        svc.config["email"]["use_tls"] = False
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host: str, port: int = 587) -> None:
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None) -> None:
                captured["context"] = context

            def login(self, username: str, password: str) -> None:
                captured["login"] = (username, password)

            def send_message(self, msg: MIMEMultipart) -> None:
                captured["message"] = msg

            def quit(self) -> None:
                captured["quit"] = True

        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        svc.config["email"]["username"] = "user"
        svc.config["email"]["password"] = "secret"
        svc.config["email"]["use_tls"] = True
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_html_email_escapes_content(self):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, host: str, port: int = 587) -> None:
                return None

            def starttls(self, context=None) -> None:
                return None

            def login(self, username: str, password: str) -> None:
                return None

            def send_message(self, msg: MIMEMultipart) -> None:
                captured["message"] = msg

            def quit(self) -> None:
                return None

        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        html_part = captured["message"].get_payload()[1].get_payload()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_attachment_outside_allowlist_is_skipped(self, tmp_path):
        captured: dict = {}
        secret = tmp_path / "secret.txt"
        secret.write_text("should-not-leak")

        class FakeSMTP:
            def __init__(self, host: str, port: int = 587) -> None:
                return None

            def starttls(self, context=None) -> None:
                return None

            def send_message(self, msg: MIMEMultipart) -> None:
                captured["message"] = msg

            def quit(self) -> None:
                return None

        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["alerts@example.com"]
        message = _message()
        message.attachments = [str(secret)]
        with patch("core.notification_service.smtplib.SMTP", FakeSMTP):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        payloads = captured["message"].get_payload()
        assert len(payloads) == 2

