"""Security tests for notification webhook URL validation."""

import asyncio
import socket

import pytest

from core.notification_service import (
    WEBHOOK_MAX_TIMEOUT_SECONDS,
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

    def test_rejects_hosts_with_any_private_dns_result(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/webhook")

    def test_webhook_timeout_is_bounded(self):
        svc = EnhancedNotificationService()

        assert svc._webhook_timeout(999).total == WEBHOOK_MAX_TIMEOUT_SECONDS
        assert svc._webhook_timeout("not-a-number").total == 10

    def test_webhook_session_disables_automatic_raise_for_status(self, monkeypatch):
        svc = EnhancedNotificationService()

        class FakeClientSession:
            def __init__(self, **kwargs):
                self.raise_for_status = kwargs["raise_for_status"]
                self.timeout = kwargs["timeout"]

        monkeypatch.setattr(
            "core.notification_service.aiohttp.ClientSession",
            FakeClientSession,
        )

        session = svc._webhook_session()

        assert session.raise_for_status is False
        assert session.timeout.total == 10


class TestWebhookDeliverySecurity:
    """Validate outbound webhook delivery hardening."""

    def test_slack_delivery_does_not_follow_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["slack"]["webhook_url"] = "https://example.com/slack"
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        session = _FakeWebhookSession(status=200)
        monkeypatch.setattr(svc, "_webhook_session", lambda configured_timeout=None: session)

        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.SLACK],
        )

        result = asyncio.run(svc._send_slack(message))

        assert result["success"] is True
        assert session.posts[0]["allow_redirects"] is False

    def test_custom_webhook_uses_bounded_timeout_and_blocks_redirects(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["webhook"].update({"url": "https://example.com/hook", "timeout": 999})
        monkeypatch.setattr(svc, "_validate_webhook_url", lambda url, allow_private=False: url)
        session = _FakeWebhookSession(status=204)

        def fake_webhook_session(configured_timeout=None):
            assert configured_timeout == 999
            return session

        monkeypatch.setattr(svc, "_webhook_session", fake_webhook_session)
        message = NotificationMessage(
            title="Test",
            content="Body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(svc._send_webhook(message))

        assert result["success"] is True
        assert session.posts[0]["allow_redirects"] is False

    def test_email_html_body_escapes_untrusted_content(self, monkeypatch):
        sent_messages = []
        monkeypatch.setattr("smtplib.SMTP", _FakeSMTP.factory(sent_messages))

        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )
        message = NotificationMessage(
            title="Security alert",
            content="<script>alert('xss')</script>",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.EMAIL],
        )

        result = asyncio.run(svc._send_email(message))

        assert result["success"] is True
        html_parts = [
            part.get_payload(decode=True).decode()
            for part in sent_messages[0].walk()
            if part.get_content_type() == "text/html"
        ]
        assert html_parts
        assert "<script>" not in html_parts[0]
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_parts[0]


class _FakeWebhookResponse:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def text(self):
        return ""


class _FakeWebhookSession:
    def __init__(self, status=200):
        self.status = status
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def post(self, url, **kwargs):
        self.posts.append({"url": url, **kwargs})
        return _FakeWebhookResponse(self.status)


class _FakeSMTP:
    def __init__(self, sent_messages, *_args, **_kwargs):
        self.sent_messages = sent_messages

    @classmethod
    def factory(cls, sent_messages):
        def _factory(*args, **kwargs):
            return cls(sent_messages, *args, **kwargs)

        return _factory

    def starttls(self):
        return None

    def login(self, *_args, **_kwargs):
        return None

    def send_message(self, msg):
        self.sent_messages.append(msg)

    def quit(self):
        return None
