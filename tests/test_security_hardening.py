"""Security hardening regression tests."""

import sys
from pathlib import Path

import pytest

# Some integration modules rely on direct imports (e.g. "social_discovery_engine").
# Ensure tests can import main_app without depending on invocation cwd.
INTEGRATIONS_DIR = Path(__file__).resolve().parent.parent / "integrations"
if str(INTEGRATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(INTEGRATIONS_DIR))

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestSafeReportPaths:
    """Ensure report file paths cannot escape intended directory."""

    def test_rejects_path_traversal_for_custom_report_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="data/reports"):
            ComprehensiveMusicDiscoveryApp._resolve_report_path("../outside.json")

    def test_allows_relative_report_name_within_reports_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = ComprehensiveMusicDiscoveryApp._resolve_report_path("nested/report.json")
        reports_root = (tmp_path / "data" / "reports").resolve()
        assert path.is_absolute()
        assert str(path).startswith(str(reports_root))


class TestDeterministicNotificationKeys:
    """Verify message dedup keys are stable and content-sensitive."""

    def test_generate_message_key_is_deterministic(self):
        svc = EnhancedNotificationService()
        msg = NotificationMessage(
            title="Security Alert",
            content="Potential issue detected in webhook delivery",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        first = svc._generate_message_key(msg)
        second = svc._generate_message_key(msg)
        assert first == second

    def test_generate_message_key_changes_when_message_changes(self):
        svc = EnhancedNotificationService()
        base = NotificationMessage(
            title="Security Alert",
            content="Payload A",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        changed = NotificationMessage(
            title="Security Alert",
            content="Payload B",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE],
        )
        assert svc._generate_message_key(base) != svc._generate_message_key(changed)


class TestStableBulkTrackCacheKey:
    """Ensure bulk query cache key is normalized and order-independent."""

    def test_bulk_track_lookup_uses_stable_normalized_cache_key(
        self, data_store, sample_trends, monkeypatch
    ):
        data_store.save_trends_bulk(sample_trends)
        captured_get_keys: list[str] = []
        captured_set_keys: list[str] = []

        original_get = data_store._cache.get
        original_set = data_store._cache.set

        def _get_spy(key):
            captured_get_keys.append(key)
            return original_get(key)

        def _set_spy(key, value, ttl=None):
            captured_set_keys.append(key)
            return original_set(key, value, ttl)

        monkeypatch.setattr(data_store._cache, "get", _get_spy)
        monkeypatch.setattr(data_store._cache, "set", _set_spy)

        pairs_one = [("Track One", "Artist A"), ("Track Two", "Artist B")]
        pairs_two = [(" track two ", "artist b"), ("TRACK ONE", "ARTIST A")]

        first = data_store.get_tracks_with_artists_bulk(pairs_one)
        second = data_store.get_tracks_with_artists_bulk(pairs_two)

        assert not first.empty
        assert not second.empty
        assert len(captured_get_keys) >= 2
        assert captured_get_keys[0] == captured_get_keys[1]
        assert captured_set_keys
        assert captured_set_keys[0] == captured_get_keys[0]
