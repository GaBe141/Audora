"""Security tests for notification webhook URL validation."""

import ssl
from unittest.mock import MagicMock

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_rejects_cgnat_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        assert svc._is_restricted_ip("::ffff:127.0.0.1") is True
        assert svc._is_restricted_ip("100.64.0.1") is True


class TestOutboundTransportHardening:
    """Webhook posts must not follow redirects; SMTP auth requires TLS."""

    def test_outbound_posts_disable_redirects(self):
        svc = EnhancedNotificationService()
        assert svc._outbound_post_kwargs()["allow_redirects"] is False

    def test_refuses_plaintext_smtp_auth(self):
        svc = EnhancedNotificationService()
        server = MagicMock()
        with pytest.raises(ValueError, match="plaintext SMTP"):
            svc._ensure_smtp_transport_security(
                server,
                {"use_tls": False, "username": "user", "password": "secret"},
            )
        server.starttls.assert_not_called()
        server.login.assert_not_called()

    def test_starttls_uses_verified_ssl_context(self):
        svc = EnhancedNotificationService()
        server = MagicMock()
        svc._ensure_smtp_transport_security(
            server,
            {"use_tls": True, "username": "user", "password": "secret"},
        )
        server.starttls.assert_called_once()
        context = server.starttls.call_args.kwargs["context"]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
