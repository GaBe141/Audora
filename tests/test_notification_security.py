"""Security tests for notification transport hardening."""

import ssl

import pytest

from core.notification_service import EnhancedNotificationService


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


class _DummySMTP:
    """Minimal SMTP stub used to assert TLS hardening behavior."""

    instances: list["_DummySMTP"] = []

    def __init__(self, host: str, port: int, timeout: int | None = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ehlo_calls = 0
        self.starttls_context = None
        self.logged_in = None
        self.sent = False
        _DummySMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self):
        self.ehlo_calls += 1

    def starttls(self, *, context):
        self.starttls_context = context

    def login(self, username: str, password: str):
        self.logged_in = (username, password)

    def send_message(self, _msg):
        self.sent = True


class TestEmailTlsSecurity:
    """Validate secure SMTP transport defaults."""

    @pytest.mark.asyncio
    async def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        _DummySMTP.instances.clear()
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", _DummySMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "port": 587,
                "username": "user",
                "password": "pass",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
                "timeout": 15,
            }
        )

        from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority

        msg = NotificationMessage(
            title="test",
            content="secure tls",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = await svc.send_notification(msg)
        assert result["delivered"] is True

        smtp = _DummySMTP.instances[-1]
        assert smtp.timeout == 15
        assert smtp.starttls_context is not None
        assert isinstance(smtp.starttls_context, ssl.SSLContext)
        assert smtp.starttls_context.verify_mode == ssl.CERT_REQUIRED
        assert smtp.starttls_context.check_hostname is True
        assert smtp.ehlo_calls >= 2
        assert smtp.sent is True
