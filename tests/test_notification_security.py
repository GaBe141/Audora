"""Security tests for webhook URL validation in notification service."""

from core.notification_service import EnhancedNotificationService


def test_webhook_validation_blocks_localhost_ip() -> None:
    """Localhost targets must be rejected to prevent SSRF into local services."""
    svc = EnhancedNotificationService()

    is_valid, reason = svc._validate_webhook_url("https://127.0.0.1:8080/hook")

    assert is_valid is False
    assert "Blocked non-public target IP" in reason


def test_webhook_validation_blocks_insecure_http_by_default() -> None:
    """HTTP should be denied unless explicitly enabled via env override."""
    svc = EnhancedNotificationService()

    is_valid, reason = svc._validate_webhook_url("http://8.8.8.8/hook")

    assert is_valid is False
    assert "HTTPS is required" in reason


def test_webhook_validation_enforces_allowed_hosts(monkeypatch) -> None:
    """Provider-specific webhooks should only allow expected domains."""
    svc = EnhancedNotificationService()
    monkeypatch.setattr(svc, "_is_public_network_host", lambda _: (True, ""))

    is_valid, reason = svc._validate_webhook_url(
        "https://example.com/hook", allowed_hosts={"hooks.slack.com"}
    )

    assert is_valid is False
    assert "Host must be one of" in reason


def test_webhook_validation_accepts_valid_slack_host(monkeypatch) -> None:
    """Expected Slack webhook host should pass validation checks."""
    svc = EnhancedNotificationService()
    monkeypatch.setattr(svc, "_is_public_network_host", lambda _: (True, ""))

    is_valid, reason = svc._validate_webhook_url(
        "https://hooks.slack.com/services/T000/B000/XXX", allowed_hosts={"hooks.slack.com"}
    )

    assert is_valid is True
    assert reason == ""
