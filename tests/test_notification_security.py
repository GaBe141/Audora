"""Security tests for outbound webhook validation."""

from core.notification_service import EnhancedNotificationService


class TestOutboundWebhookValidation:
    """Ensure webhook targets are validated before outbound requests."""

    def test_rejects_non_https(self):
        svc = EnhancedNotificationService()
        is_valid, reason = svc._validate_outbound_webhook_url("http://hooks.slack.com/services/abc")
        assert is_valid is False
        assert "HTTPS" in reason

    def test_rejects_localhost(self):
        svc = EnhancedNotificationService()
        is_valid, reason = svc._validate_outbound_webhook_url("https://localhost/webhook")
        assert is_valid is False
        assert "Localhost" in reason

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        is_valid, reason = svc._validate_outbound_webhook_url(
            "https://user:pass@hooks.slack.com/services/abc"
        )
        assert is_valid is False
        assert "credentials" in reason

    def test_rejects_private_resolution(self, monkeypatch):
        svc = EnhancedNotificationService()

        def _private_host(*_args, **_kwargs):
            return [(0, 0, 0, "", ("10.0.0.15", 443))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _private_host)
        is_valid, reason = svc._validate_outbound_webhook_url("https://hooks.slack.com/services/abc")
        assert is_valid is False
        assert "non-public" in reason

    def test_accepts_public_resolution(self, monkeypatch):
        svc = EnhancedNotificationService()

        def _public_host(*_args, **_kwargs):
            return [(0, 0, 0, "", ("52.23.19.8", 443))]

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _public_host)
        is_valid, reason = svc._validate_outbound_webhook_url("https://hooks.slack.com/services/abc")
        assert is_valid is True
        assert reason == ""
