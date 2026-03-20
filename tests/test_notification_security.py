"""Security-focused tests for notification URL validation."""

from core.notification_service import validate_outbound_url


def test_validate_outbound_url_rejects_insecure_http():
    ok, reason = validate_outbound_url("http://hooks.slack.com/services/test")
    assert ok is False
    assert "HTTPS" in reason


def test_validate_outbound_url_rejects_localhost():
    ok, reason = validate_outbound_url("https://localhost/webhook")
    assert ok is False
    assert "Private or local network targets are blocked" in reason


def test_validate_outbound_url_rejects_private_ip():
    ok, reason = validate_outbound_url("https://10.0.0.5/webhook")
    assert ok is False
    assert "Private or local network targets are blocked" in reason


def test_validate_outbound_url_allows_private_when_explicitly_enabled():
    ok, _ = validate_outbound_url(
        "https://10.0.0.5/webhook", allow_private_targets=True
    )
    assert ok is True


def test_validate_outbound_url_allows_https_public_host(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(None, None, None, None, ("8.8.8.8", 0))]

    monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
    ok, reason = validate_outbound_url("https://hooks.slack.com/services/test")
    assert ok is True
    assert reason == ""
