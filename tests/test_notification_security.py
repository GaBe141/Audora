"""Security tests for notification SSRF hardening via source assertions."""

from pathlib import Path


def _notification_source() -> str:
    return Path("core/notification_service.py").read_text(encoding="utf-8")


def test_webhook_url_validation_keeps_https_and_restricted_network_checks():
    """Ensure key SSRF validation guards remain in place."""
    source = _notification_source()
    assert 'if parsed.scheme != "https":' in source
    assert "Localhost webhook URLs are not allowed" in source
    assert "private or restricted network address" in source


def test_webhook_channels_disable_redirects():
    """Ensure outbound webhook calls do not follow redirects."""
    source = _notification_source()
    # Slack, Discord and custom webhook paths should all disable redirects.
    assert source.count("allow_redirects=False") >= 3
