"""Security tests for notification webhook URL validation."""

import asyncio
import ssl

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _sample_message(channel: NotificationChannel) -> NotificationMessage:
    return NotificationMessage(
        title="Test",
        content="hello <script>alert(1)</script>",
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

    def test_rejects_link_local_metadata_ip(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest/meta-data/")

    def test_rejects_ipv6_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::1]/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookRedirectHardening:
    """Outbound webhooks must not follow redirects to private hosts."""

    def _patch_session(self, monkeypatch, captured: dict):
        class DummyResponse:
            status = 200

            async def text(self):
                return "ok"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class DummySession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return DummyResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", DummySession)

    def test_custom_webhook_disables_redirects(self, monkeypatch):
        captured: dict = {}
        self._patch_session(monkeypatch, captured)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        result = asyncio.run(svc._send_webhook(_sample_message(NotificationChannel.WEBHOOK)))
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False

    def test_slack_webhook_disables_redirects(self, monkeypatch):
        captured: dict = {}
        self._patch_session(monkeypatch, captured)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        result = asyncio.run(svc._send_slack(_sample_message(NotificationChannel.SLACK)))
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False

    def test_discord_webhook_disables_redirects(self, monkeypatch):
        captured: dict = {}
        self._patch_session(monkeypatch, captured)
        svc = EnhancedNotificationService()
        svc._validate_webhook_url = lambda url, *, allow_private=False: url
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        result = asyncio.run(svc._send_discord(_sample_message(NotificationChannel.DISCORD)))
        assert result["success"] is True
        assert captured["kwargs"].get("allow_redirects") is False


class TestSmtpTransportSecurity:
    """SMTP must use verified TLS and must not send credentials in plaintext."""

    def test_rejects_plaintext_smtp_auth_without_tls(self):
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
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        captured: dict = {}

        class DummySMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port

            def starttls(self, context=None):
                captured["context"] = context

            def login(self, username, password):
                captured["login"] = (username, password)

            def send_message(self, msg):
                captured["html"] = msg.get_payload()[1].get_payload(decode=True).decode("utf-8")

            def quit(self):
                captured["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
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
        result = asyncio.run(svc._send_email(_sample_message(NotificationChannel.EMAIL)))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert "&lt;script&gt;" in captured["html"]
        assert "<script>" not in captured["html"]
