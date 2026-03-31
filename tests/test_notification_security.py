"""Security tests for notification webhook URL validation."""

import asyncio
import socket

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

    def test_rejects_hosts_not_in_explicit_allowlist(self, monkeypatch):
        svc = EnhancedNotificationService()

        def _mock_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
        with pytest.raises(ValueError, match="allowed host list"):
            svc._validate_webhook_url(
                "https://example.com/webhook",
                allow_private=False,
                allowed_hosts={"hooks.slack.com"},
            )

    def test_allows_subdomains_in_explicit_allowlist(self, monkeypatch):
        svc = EnhancedNotificationService()

        def _mock_getaddrinfo(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
        url = "https://sub.example.com/webhook"
        assert (
            svc._validate_webhook_url(
                url,
                allow_private=False,
                allowed_hosts={"example.com"},
            )
            == url
        )

    def test_http_session_disables_env_proxy_usage(self):
        svc = EnhancedNotificationService()
        session = svc._build_http_session()
        try:
            assert session.trust_env is False
        finally:
            asyncio.run(session.close())
