"""Security checks for GUI actions that accept client-supplied values."""

import pytest

from core.notification_service import EnhancedNotificationService
from gui.app import _apply_channel_urls, _demo_args, _history_csv


def test_demo_arguments_are_allowlisted():
    command = _demo_args("trending")
    assert command[-2:] == ["--demo", "trending"]
    with pytest.raises(ValueError, match="Unsupported demo"):
        _demo_args("statistical;touch /tmp/pwned")
    with pytest.raises(ValueError, match="Unsupported demo"):
        _demo_args(None)


def test_history_csv_neutralizes_formulas_and_caps_rows():
    exported = _history_csv([{"track": "=1+1", "artist": "Ada"}])
    assert "'=1+1" in exported
    with pytest.raises(ValueError, match="exceeds"):
        _history_csv([{"track": "ok"}] * 100_001)


def test_settings_reject_loopback_webhook():
    service = EnhancedNotificationService()
    with pytest.raises(ValueError, match="private or restricted"):
        _apply_channel_urls(service, None, None, "https://127.0.0.1/hook")
