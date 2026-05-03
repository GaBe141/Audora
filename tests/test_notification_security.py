"""Security tests for notification webhook URL validation."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from core.notification_service import EnhancedNotificationService


class _FakePostContext:
    def __init__(self, response=None, error: Exception | None = None):
        self.response = response
        self.error = error

    async def __aenter__(self):
        if self.error:
            raise self.error
        return self.response

    async def __aexit__(self, _exc_type, _exc, _tb):
        return None


class _FakeSession:
    def __init__(self, response=None, error: Exception | None = None):
        self.closed = False
        self.post_calls = []
        self.response = response
        self.error = error

    def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        return _FakePostContext(self.response, self.error)

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        self.closed = True
        return None


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

    def test_validation_records_vetted_dns_answers(self):
        svc = EnhancedNotificationService()
        with patch(
            "core.notification_service.socket.getaddrinfo",
            return_value=[
                (
                    None,
                    None,
                    None,
                    None,
                    ("93.184.216.34", 443),
                )
            ],
        ):
            target = svc._validate_webhook_target("https://example.com/webhook")

        assert target.hostname == "example.com"
        assert target.port == 443
        assert target.resolved_ips == ("93.184.216.34",)

    @pytest.mark.asyncio
    async def test_post_uses_pinned_resolver_and_disables_redirects(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_target("https://10.0.0.1/webhook", allow_private=True)

        response = Mock(status=204, text=AsyncMock(return_value=""))

        with patch.object(svc, "_webhook_session") as session_factory:
            session = _FakeSession(response=response)
            session_factory.return_value = session

            status, body = await svc._post_validated_webhook(target, json_payload={"ok": True})

        assert (status, body) == (204, "")
        assert session.closed is True
        assert session.post_calls == [
            (
                (target.url,),
                {
                    "json": {"ok": True},
                    "headers": None,
                    "timeout": None,
                    "allow_redirects": False,
                },
            )
        ]

    @pytest.mark.asyncio
    async def test_post_closes_session_when_request_fails(self):
        svc = EnhancedNotificationService()
        target = svc._validate_webhook_target("https://10.0.0.1/webhook", allow_private=True)

        with patch.object(svc, "_webhook_session") as session_factory:
            session = _FakeSession(error=RuntimeError("blocked"))
            session_factory.return_value = session

            with pytest.raises(RuntimeError, match="blocked"):
                await svc._post_validated_webhook(target, json_payload={})

        assert session.closed is True
