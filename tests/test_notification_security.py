"""Security tests for notification webhook URL validation and transport hardening."""

import asyncio
import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationMessage,
    NotificationPriority,
)


def _public_addrinfo(*_args, **_kwargs):
    return [(0, 0, 0, "", ("93.184.216.34", 443))]


def _addrinfo_for(ip: str):
    def _inner(*_args, **_kwargs):
        return [(0, 0, 0, "", (ip, 443))]

    return _inner


class _FakeResponse:
    def __init__(self, status: int = 200, body: str = "ok"):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _FakeSession:
    def __init__(self, status: int = 200):
        self.status = status
        self.post_kwargs: dict = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def post(self, url, **kwargs):
        self.post_kwargs = {"url": url, **kwargs}
        _FakeSession.last_kwargs = self.post_kwargs
        return _FakeResponse(self.status)


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

    def test_rejects_localhost_subdomain(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://foo.localhost/webhook")

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_cgnat_targets(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            _addrinfo_for("100.64.0.1"),
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://cgnat.example/webhook")

    def test_rejects_ipv4_mapped_private_targets(self, monkeypatch):
        svc = EnhancedNotificationService()
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            _addrinfo_for("::ffff:10.0.0.1"),
        )
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://mapped.example/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url


class TestWebhookTransportHardening:
    """Outbound webhook posts must not follow redirects."""

    def test_slack_disables_redirects(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo", _public_addrinfo
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.example.com/services/T/B/X"
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_slack(message))
        assert result["success"] is True
        assert _FakeSession.last_kwargs.get("allow_redirects") is False

    def test_discord_disables_redirects(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo", _public_addrinfo
        )
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.example.com/api/webhooks/1/2"
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_discord(message))
        assert result["success"] is True
        assert _FakeSession.last_kwargs.get("allow_redirects") is False

    def test_custom_webhook_rejects_redirect_status(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo", _public_addrinfo
        )
        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            lambda: _FakeSession(status=302),
        )
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://hooks.example.com/custom"
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is False
        assert "Redirect rejected" in result["error"]


class TestSmtpTransportSecurity:
    """SMTP authentication must not occur on plaintext connections."""

    def test_rejects_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 25,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": False,
        }
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is False
        assert "TLS" in result["error"]

    def test_starttls_uses_verified_ssl_context(self):
        smtp = MagicMock()
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "user",
            "password": "pass",
            "from_address": "a@example.com",
            "recipients": ["b@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="t",
            content="c",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        smtp.starttls.assert_called_once()
        context = smtp.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED


class TestAttachmentPathGuard:
    """Email attachments must stay inside the project root."""

    def test_rejects_path_outside_project(self, tmp_path):
        svc = EnhancedNotificationService()
        outside = tmp_path / "secret.txt"
        outside.write_text("nope", encoding="utf-8")
        assert svc._is_safe_attachment_path(str(outside)) is False

    def test_allows_path_inside_project(self):
        svc = EnhancedNotificationService()
        readme = Path(__file__).resolve().parent.parent / "README.md"
        assert svc._is_safe_attachment_path(str(readme)) is True
