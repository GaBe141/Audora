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

    def test_rejects_cgnat_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [(0, 0, 0, "", ("100.64.0.1", 443))]

        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://cgnat.example/webhook")

    def test_rejects_ipv4_mapped_loopback(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [(0, 0, 0, "", ("::ffff:127.0.0.1", 443, 0, 0))]

        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://mapped.example/webhook")


class TestWebhookRedirectHardening:
    """Outbound webhook clients must not follow redirects."""

    def _install_fake_session(self, monkeypatch, recorded: dict, status: int = 200):
        class FakeResponse:
            def __init__(self) -> None:
                self.status = status

            async def text(self) -> str:
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                recorded["url"] = url
                recorded.update(kwargs)
                return FakeResponse()

        monkeypatch.setattr("aiohttp.ClientSession", FakeSession)
        monkeypatch.setattr(
            "socket.getaddrinfo",
            lambda *args, **kwargs: [(0, 0, 0, "", ("1.1.1.1", 443))],
        )

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        recorded: dict = {}
        self._install_fake_session(monkeypatch, recorded)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert recorded.get("allow_redirects") is False

    def test_slack_disables_redirects(self, monkeypatch):
        recorded: dict = {}
        self._install_fake_session(monkeypatch, recorded)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        result = asyncio.run(svc._send_slack(_message()))
        assert result["success"] is True
        assert recorded.get("allow_redirects") is False

    def test_discord_disables_redirects(self, monkeypatch):
        recorded: dict = {}
        self._install_fake_session(monkeypatch, recorded)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        result = asyncio.run(svc._send_discord(_message()))
        assert result["success"] is True
        assert recorded.get("allow_redirects") is False

    def test_rejects_redirect_status(self, monkeypatch):
        recorded: dict = {}
        self._install_fake_session(monkeypatch, recorded, status=302)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/hook"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirect" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP authentication must not occur on plaintext connections."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, *args):
                captured["login"] = True

            def send_message(self, msg):
                captured["message"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        assert isinstance(captured["context"], ssl.SSLContext)
        assert captured["context"].check_hostname is True
        assert captured["context"].verify_mode == ssl.CERT_REQUIRED

    def test_html_body_is_escaped(self, monkeypatch):
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                pass

            def send_message(self, msg):
                captured["message"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        html_part = captured["message"].get_payload()[1].get_payload(decode=True).decode()
        assert "<script>" not in html_part
        assert "&lt;script&gt;" in html_part

    def test_rejects_attachments_outside_project_root(self, tmp_path, monkeypatch):
        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        captured: dict = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                pass

            def send_message(self, msg):
                captured["message"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        msg = _message()
        msg.attachments = [str(outside)]
        result = asyncio.run(svc._send_email(msg))
        assert result["success"] is True
        assert isinstance(captured["message"], MIMEMultipart)
        assert len(captured["message"].get_payload()) == 2
