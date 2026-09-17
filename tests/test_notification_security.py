"""Security tests for notification webhook, SMTP, and attachment handling."""

import asyncio
import ssl
from email.mime.multipart import MIMEMultipart

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


def _message(**overrides) -> NotificationMessage:
    defaults = {
        "title": "Alert",
        "content": "hello",
        "priority": NotificationPriority.LOW,
        "channels": [],
    }
    defaults.update(overrides)
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
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_cgnat_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [
                (0, 0, 0, "", ("100.64.0.1", 443)),
            ],
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/webhook")

    def test_rejects_ipv4_mapped_private_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [
                (0, 0, 0, "", ("::ffff:10.0.0.1", 443)),
            ],
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/webhook")


class TestRestrictedIpClassification:
    """Restricted IPs include CGNAT and IPv4-mapped private addresses."""

    def test_cgnat_is_restricted(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("100.64.0.1") is True

    def test_public_ipv4_is_allowed(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("8.8.8.8") is False

    def test_ipv4_mapped_private_is_restricted(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:192.168.1.20") is True

    def test_loopback_is_restricted(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("127.0.0.1") is True


class TestWebhookRedirectHardening:
    """Outbound webhook POSTs must not follow redirects."""

    def test_slack_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 200

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
                captured["kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: FakeSession(),
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
        assert captured["kwargs"]["allow_redirects"] is False

    def test_discord_rejects_redirect_status(self, monkeypatch):
        class FakeResponse:
            status = 302

            async def text(self) -> str:
                return "redirect"

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
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: FakeSession(),
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://hooks.example.com/discord"
        result = asyncio.run(svc._send_discord(_message()))
        assert result["success"] is False
        assert "Redirect" in result["error"]

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 200

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
                captured["kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda *args, **kwargs: FakeSession(),
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is True
        assert captured["kwargs"]["allow_redirects"] is False


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS before transmitting credentials."""

    def test_rejects_plaintext_smtp_auth(self):
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
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
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
        result = asyncio.run(svc._send_email(_message(content="<script>alert(1)</script>")))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        msg = captured["msg"]
        assert isinstance(msg, MIMEMultipart)
        html_parts = [part for part in msg.get_payload() if part.get_content_type() == "text/html"]
        assert html_parts
        html_body = html_parts[0].get_payload(decode=True).decode("utf-8")
        assert "<script>" not in html_body
        assert "&lt;script&gt;" in html_body


class TestEmailAttachmentSafety:
    """Email attachments must stay inside the project tree."""

    def test_rejects_paths_outside_project(self):
        svc = EnhancedNotificationService()
        assert svc._is_safe_attachment("/etc/passwd") is False
        assert svc._is_safe_attachment("../etc/passwd") is False

    def test_outside_attachments_are_skipped(self, monkeypatch, tmp_path):
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self, context=None):
                pass

            def send_message(self, msg):
                captured["msg"] = msg

            def quit(self):
                pass

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        result = asyncio.run(svc._send_email(_message(attachments=[str(outside)])))
        assert result["success"] is True
        attached = [
            part
            for part in captured["msg"].walk()
            if part.get_content_disposition() == "attachment"
        ]
        assert attached == []
