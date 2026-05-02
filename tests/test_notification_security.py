"""Security tests for notification transports and webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
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

    def test_rejects_embedded_credentials(self, mocker):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return ""


class _FakeSession:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return _FakeResponse()


class TestNotificationTransportSecurity:
    """Validate secure transport behavior for outbound notifications."""

    @pytest.fixture(autouse=True)
    def clear_calls(self):
        _FakeSession.calls = []

    @pytest.fixture
    def message(self):
        return NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

    def test_slack_disables_redirects(self, mocker, message):
        mocker.patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 443))],
        )
        mocker.patch("aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert _FakeSession.calls[0][1]["allow_redirects"] is False

    def test_discord_disables_redirects(self, mocker, message):
        mocker.patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 443))],
        )
        mocker.patch("aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["discord"]["webhook_url"] = "https://example.com/discord"

        result = asyncio.run(svc._send_discord(message))

        assert result["success"] is True
        assert _FakeSession.calls[0][1]["allow_redirects"] is False

    def test_custom_webhook_disables_redirects(self, mocker, message):
        mocker.patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 443))],
        )
        mocker.patch("aiohttp.ClientSession", _FakeSession)
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/custom"

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert _FakeSession.calls[0][1]["allow_redirects"] is False

    def test_email_rejects_plaintext_auth(self, message):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": False,
            }
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is False
        assert "without TLS" in result["error"]

    def test_email_starttls_uses_validating_ssl_context(self, mocker, message):
        smtp = mocker.MagicMock()
        mocker.patch("smtplib.SMTP", return_value=smtp)
        context_factory = mocker.patch(
            "ssl.create_default_context", return_value=mocker.sentinel.context
        )
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["to@example.com"],
                "username": "user",
                "password": "password",
                "use_tls": True,
            }
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        context_factory.assert_called_once_with()
        smtp.starttls.assert_called_once_with(context=mocker.sentinel.context)
