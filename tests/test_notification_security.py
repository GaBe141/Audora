"""Security tests for outbound notification URL validation."""

from core.notification_service import EnhancedNotificationService


def test_webhook_url_rejects_non_https():
    service = EnhancedNotificationService()
    ok, error = service._is_safe_webhook_url("http://example.com/webhook")
    assert ok is False
    assert "https" in error


def test_webhook_url_rejects_localhost():
    service = EnhancedNotificationService()
    ok, error = service._is_safe_webhook_url("https://localhost/webhook")
    assert ok is False
    assert "local" in error.lower()


def test_webhook_url_rejects_private_ip_resolution(monkeypatch):
    service = EnhancedNotificationService()

    def _fake_private_resolution(*_args, **_kwargs):
        return [(None, None, None, None, ("10.0.0.5", 443))]

    monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _fake_private_resolution)
    ok, error = service._is_safe_webhook_url("https://hooks.example.test/path")
    assert ok is False
    assert "non-public" in error


def test_webhook_url_allows_public_resolution(monkeypatch):
    service = EnhancedNotificationService()

    def _fake_public_resolution(*_args, **_kwargs):
        return [(None, None, None, None, ("93.184.216.34", 443))]

    monkeypatch.setattr("core.notification_service.socket.getaddrinfo", _fake_public_resolution)
    ok, error = service._is_safe_webhook_url("https://hooks.example.test/path")
    assert ok is True
    assert error == ""
