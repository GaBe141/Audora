"""Regression tests for security hardening changes."""

import hashlib
import json

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from scripts.fix_linting_issues import run_command


def test_cache_manager_build_cache_key_is_deterministic_and_sha256(mock_cache):
    """Cache key hashing should be deterministic and use SHA-256 digests."""
    args = ({"artist": "A", "track": "Song"}, 123)
    kwargs = {"platform": "spotify", "days": 7}

    key_one = mock_cache._build_cache_key("prefix", args, kwargs)
    key_two = mock_cache._build_cache_key("prefix", args, {"days": 7, "platform": "spotify"})

    assert key_one == key_two

    expected_args_digest = hashlib.sha256(
        json.dumps(args, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    expected_kwargs_digest = hashlib.sha256(
        json.dumps(kwargs, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    assert key_one == f"prefix:{expected_args_digest}:{expected_kwargs_digest}"


def test_notification_message_key_is_stable_and_priority_sensitive():
    """Notification dedupe keys should be stable and change with priority."""
    svc = EnhancedNotificationService()

    high_message = NotificationMessage(
        title="Security alert",
        content="Potential issue detected",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.CONSOLE],
    )
    low_message = NotificationMessage(
        title="Security alert",
        content="Potential issue detected",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.CONSOLE],
    )

    high_key_first = svc._generate_message_key(high_message)
    high_key_second = svc._generate_message_key(high_message)
    low_key = svc._generate_message_key(low_message)

    assert high_key_first == high_key_second
    assert len(high_key_first) == 64
    assert all(c in "0123456789abcdef" for c in high_key_first)
    assert high_key_first != low_key


def test_data_store_bulk_track_cache_key_stable_across_input_order(data_store, sample_trends):
    """Bulk track cache key should be deterministic regardless of pair ordering."""
    data_store.save_trends_bulk(sample_trends)
    pairs = [(sample_trends[0].track_name, sample_trends[0].artist),
             (sample_trends[1].track_name, sample_trends[1].artist)]

    result_one = data_store.get_tracks_with_artists_bulk(pairs)
    result_two = data_store.get_tracks_with_artists_bulk(list(reversed(pairs)))

    assert not result_one.empty
    assert result_one.equals(result_two)

    pairs_digest = hashlib.sha256(
        json.dumps(sorted(pairs), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert data_store._cache.exists(f"tracks_bulk:{pairs_digest}")


def test_fix_linting_run_command_avoids_shell(monkeypatch):
    """run_command must execute without shell=True to avoid command injection."""
    observed = {}

    def fake_run(cmd, **kwargs):
        observed["cmd"] = cmd
        observed["kwargs"] = kwargs

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)

    assert run_command(["python", "--version"], "check python version") is True
    assert observed["cmd"] == ["python", "--version"]
    assert observed["kwargs"].get("shell") is None
    assert observed["kwargs"]["check"] is True
    assert observed["kwargs"]["capture_output"] is True
    assert observed["kwargs"]["text"] is True
