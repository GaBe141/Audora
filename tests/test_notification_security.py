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


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    def __init__(self, status=200):
        self.status = status
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return _FakeResponse(status=self.status)


def _message() -> NotificationMessage:
    return NotificationMessage(
        title="Security test",
        content="Test content",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.CONSOLE],
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
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class TestWebhookTransportHardening:
    """Validate outbound webhook transports do not follow redirects."""

    def test_slack_send_disables_redirects(self, monkeypatch):
        created_sessions = []

        def fake_client_session():
            session = _FakeSession()
            created_sessions.append(session)
            return session

        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", fake_client_session)

        result = asyncio.run(svc._send_slack(_message()))

        assert result["success"] is True
        assert created_sessions[0].post_calls[0][1]["allow_redirects"] is False

    def test_discord_send_disables_redirects(self, monkeypatch):
        created_sessions = []

        def fake_client_session():
            session = _FakeSession(status=204)
            created_sessions.append(session)
            return session

        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://discord.com/api/webhooks/test"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", fake_client_session)

        result = asyncio.run(svc._send_discord(_message()))

        assert result["success"] is True
        assert created_sessions[0].post_calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_send_disables_redirects(self, monkeypatch):
        created_sessions = []

        def fake_client_session():
            session = _FakeSession()
            created_sessions.append(session)
            return session

        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", fake_client_session)

        result = asyncio.run(svc._send_webhook(_message()))

        assert result["success"] is True
        assert created_sessions[0].post_calls[0][1]["allow_redirects"] is False


class TestEmailTransportHardening:
    """Validate SMTP transport security for credentials and STARTTLS."""

    def test_starttls_uses_verified_ssl_context(self, monkeypatch):
        smtp_instances = []

        class FakeSMTP:
            def __init__(self, server, port):
                self.starttls_context = None
                smtp_instances.append(self)

            def starttls(self, context=None):
                self.starttls_context = context

            def login(self, username, password):
                pass

            def send_message(self, message):
                pass

            def quit(self):
                pass

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": True,
            }
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is True
        assert isinstance(smtp_instances[0].starttls_context, ssl.SSLContext)
        assert smtp_instances[0].starttls_context.check_hostname is True

    def test_refuses_plaintext_smtp_auth(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, server, port):
                self.login_called = False
                self.quit_called = False

            def login(self, username, password):
                self.login_called = True

            def send_message(self, message):
                pass

            def quit(self):
                self.quit_called = True

        smtp_instances = []

        def fake_smtp(*args, **kwargs):
            smtp = FakeSMTP(*args, **kwargs)
            smtp_instances.append(smtp)
            return smtp

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "username": "user",
                "password": "secret",
                "use_tls": False,
            }
        )
        monkeypatch.setattr("core.notification_service.smtplib.SMTP", fake_smtp)

        result = asyncio.run(svc._send_email(_message()))

        assert result["success"] is False
        assert "without TLS" in result["error"]
        assert smtp_instances[0].login_called is False
        assert smtp_instances[0].quit_called is True
