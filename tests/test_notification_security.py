"""Security tests for notification webhook URL validation."""

import asyncio
from email import message_from_string

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    _RestrictedWebhookResolver,
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

    def test_resolver_rejects_private_addresses_after_initial_validation(self):
        resolver = _RestrictedWebhookResolver(allow_private=False)

        class FakeResolver:
            async def resolve(self, host, port=0, family=0):
                return [
                    {
                        "hostname": host,
                        "host": "127.0.0.1",
                        "port": port,
                        "family": family,
                        "proto": 0,
                        "flags": 0,
                    }
                ]

            async def close(self):
                return None

        resolver._resolver = FakeResolver()

        async def resolve_private_address():
            with pytest.raises(OSError, match="private or restricted"):
                await resolver.resolve("example.com", 443)

        asyncio.run(resolve_private_address())
        asyncio.run(resolver.close())

    def test_rejects_redirect_responses_instead_of_following(self, monkeypatch):
        svc = EnhancedNotificationService()

        async def fake_post(url, payload, *, allow_private, **kwargs):
            assert allow_private is False
            return 302, "redirect"

        monkeypatch.setattr(svc, "_post_webhook_json", fake_post)
        svc.config["slack"]["webhook_url"] = "https://hooks.slack.com/services/test"

        message = NotificationMessage(
            title="Redirect attempt",
            content="content",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is False
        assert result["error"] == "HTTP 302: redirect"

    def test_resolver_allows_private_addresses_when_explicitly_enabled(self):
        resolver = _RestrictedWebhookResolver(allow_private=True)

        class FakeResolver:
            async def resolve(self, host, port=0, family=0):
                return [{"host": "127.0.0.1", "port": port}]

            async def close(self):
                return None

        resolver._resolver = FakeResolver()

        async def resolve_private_address():
            assert await resolver.resolve("example.com", 443) == [{"host": "127.0.0.1", "port": 443}]

        asyncio.run(resolve_private_address())
        asyncio.run(resolver.close())

    def test_post_webhook_json_disables_redirects_and_uses_restricted_resolver(self, monkeypatch):
        captured = {}
        response = FakeWebhookResponse(status=200, body="ok")

        class FakeSession:
            def __init__(self, *, connector, timeout):
                captured["connector"] = connector
                captured["timeout"] = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["kwargs"] = kwargs
                return response

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        svc = EnhancedNotificationService()

        status, body = asyncio.run(
            svc._post_webhook_json(
                "https://example.com/webhook",
                {"ok": True},
                headers={"Content-Type": "application/json"},
            )
        )

        assert status == 200
        assert body == "ok"
        assert captured["url"] == "https://example.com/webhook"
        assert captured["kwargs"]["allow_redirects"] is False
        assert isinstance(captured["connector"]._resolver, _RestrictedWebhookResolver)

    def test_email_html_content_is_escaped(self, monkeypatch):
        sent_messages = []

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def starttls(self):
                return None

            def login(self, username, password):
                return None

            def send_message(self, msg):
                sent_messages.append(msg)

            def quit(self):
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        message = NotificationMessage(
            title="Unsafe content",
            content='<img src=x onerror="alert(1)">',
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        assert sent_messages

        raw_message = sent_messages[0].as_string()
        parsed_message = message_from_string(raw_message)
        html_part = next(
            part for part in parsed_message.walk() if part.get_content_type() == "text/html"
        )
        html_payload = html_part.get_payload(decode=True).decode()

        assert '<img src=x onerror="alert(1)">' not in html_payload
        assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_payload
