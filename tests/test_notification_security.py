"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl

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
        content="Hello <script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.WEBHOOK],
    )


def _addrinfo(ip: str, port: int = 443):
    if ":" in ip:
        return [(0, 0, 0, "", (ip, port, 0, 0))]
    return [(0, 0, 0, "", (ip, port))]


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

    def test_rejects_cgnat_shared_address_space(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: _addrinfo("100.64.0.1"),
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://cgnat.example/webhook")

    def test_rejects_ipv4_mapped_loopback(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: _addrinfo("::ffff:127.0.0.1"),
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://mapped.example/webhook")


class _DummyResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def text(self) -> str:
        return "ok"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _DummySession:
    def __init__(self, capture: dict):
        self.capture = capture

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json=None, **kwargs):
        self.capture["url"] = url
        self.capture["json"] = json
        self.capture["kwargs"] = kwargs
        return _DummyResponse(self.capture.get("status", 200))


class TestWebhookTransportHardening:
    """Outbound webhook requests must not follow redirects."""

    def test_slack_disables_redirects(self, monkeypatch):
        capture: dict = {}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(capture),
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        result = asyncio.run(svc._send_slack(_message()))
        assert result["success"] is True
        assert capture["kwargs"].get("allow_redirects") is False

    def test_discord_disables_redirects(self, monkeypatch):
        capture: dict = {"status": 204}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(capture),
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
        assert capture["kwargs"].get("allow_redirects") is False

    def test_custom_webhook_rejects_redirect_status(self, monkeypatch):
        capture: dict = {"status": 302}
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _DummySession(capture),
        )
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_webhook_url",
            lambda self, url, allow_private=False: url,
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        result = asyncio.run(svc._send_webhook(_message()))
        assert result["success"] is False
        assert "Redirect" in result["error"]
        assert capture["kwargs"].get("allow_redirects") is False


class TestSmtpTransportSecurity:
    """SMTP must use validated TLS and must not send credentials in plaintext."""

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "secret",
            "from_address": "music@example.com",
            "recipients": ["alerts@example.com"],
            "use_tls": False,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_default_ssl_context(self, monkeypatch):
        recorded: dict = {}

        class DummySMTP:
            def __init__(self, host, port):
                recorded["host"] = host
                recorded["port"] = port

            def starttls(self, context=None):
                recorded["context"] = context

            def login(self, username, password):
                recorded["login"] = (username, password)

            def send_message(self, msg):
                recorded["html"] = msg.as_string()

            def quit(self):
                recorded["quit"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", DummySMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "secret",
            "from_address": "music@example.com",
            "recipients": ["alerts@example.com"],
            "use_tls": True,
        }
        result = asyncio.run(svc._send_email(_message()))
        assert result["success"] is True
        assert recorded["context"] is not None
        assert recorded["context"].check_hostname is True
        assert recorded["context"].verify_mode == ssl.CERT_REQUIRED
        assert recorded["login"] == ("user", "secret")
        assert "&lt;script&gt;" in recorded["html"]
