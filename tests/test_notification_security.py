"""Security tests for notification transport hardening."""

import asyncio
import ssl
from email.mime.text import MIMEText

import aiohttp
import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    PinnedWebhookResolver,
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

    def test_webhook_target_pins_validated_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto):
            assert host == "example.com"
            assert port == 443
            assert proto == 6
            return [(2, 1, 6, "", ("93.184.216.34", 443))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)

        target = svc._validate_webhook_target("https://example.com/webhook")

        assert target.url == "https://example.com/webhook"
        assert target.resolved_addresses == ((2, "93.184.216.34", 443, 6, 0),)

    def test_pinned_resolver_reuses_validated_ip(self, monkeypatch):
        svc = EnhancedNotificationService()

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
        )
        target = svc._validate_webhook_target("https://example.com/webhook")
        resolver = PinnedWebhookResolver(target)

        resolved = asyncio.run(resolver.resolve("example.com", 443))

        assert resolved == [
            {
                "hostname": "example.com",
                "host": "93.184.216.34",
                "port": 443,
                "family": 2,
                "proto": 6,
                "flags": 0,
            }
        ]


class TestNotificationDeliverySecurity:
    """Validate security-sensitive notification send behavior."""

    def test_custom_webhook_uses_pinned_connector_and_disables_redirects(
        self, monkeypatch
    ):
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
        )

        captured = {}

        class FakeResponse:
            status = 204

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            async def text(self):
                return ""

        class FakeSession:
            def __init__(self, *args, **kwargs):
                captured["connector"] = kwargs.get("connector")

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["allow_redirects"] = kwargs.get("allow_redirects")
                return FakeResponse()

        monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)

        result = asyncio.run(
            svc._send_webhook(
                NotificationMessage(
                    title="test",
                    content="body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.WEBHOOK],
                )
            )
        )

        assert result["success"] is True
        assert captured["url"] == "https://example.com/webhook"
        assert captured["allow_redirects"] is False
        assert isinstance(captured["connector"]._resolver, PinnedWebhookResolver)

    def test_email_html_body_escapes_untrusted_content(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
                "username": "",
                "password": "",
            }
        )
        sent_messages = []

        class FakeSMTP:
            def __init__(self, host, port):
                self.host = host
                self.port = port

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="alert",
                    content='<img src=x onerror="alert(1)">',
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        html_parts = [
            part
            for part in sent_messages[0].walk()
            if isinstance(part, MIMEText) and part.get_content_subtype() == "html"
        ]
        assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_parts[0].get_payload()
        assert "<img src=x" not in html_parts[0].get_payload()

    def test_email_starttls_uses_verified_ssl_context(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": True,
                "username": "",
                "password": "",
            }
        )
        contexts = []

        class FakeSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self, *, context):
                contexts.append(context)

            def send_message(self, msg):
                return None

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        result = asyncio.run(
            svc._send_email(
                NotificationMessage(
                    title="alert",
                    content="body",
                    priority=NotificationPriority.LOW,
                    channels=[NotificationChannel.EMAIL],
                )
            )
        )

        assert result["success"] is True
        assert len(contexts) == 1
        assert isinstance(contexts[0], ssl.SSLContext)
        assert contexts[0].check_hostname is True
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED
