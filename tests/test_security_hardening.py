"""Security hardening regression tests."""

import hashlib
import json
from unittest.mock import patch

from core.data_store import EnhancedMusicDataStore
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestMessageKeyDeterminism:
    """Ensure message dedupe key is deterministic and content-based."""

    def test_generate_message_key_is_deterministic(self):
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="Critical alert",
            content="A suspicious condition was detected",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.SLACK, NotificationChannel.WEBHOOK],
        )
        assert svc._generate_message_key(message) == svc._generate_message_key(message)

    def test_generate_message_key_changes_with_content(self):
        svc = EnhancedNotificationService()
        message_a = NotificationMessage(
            title="Critical alert",
            content="Condition A",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.SLACK],
        )
        message_b = NotificationMessage(
            title="Critical alert",
            content="Condition B",
            priority=NotificationPriority.CRITICAL,
            channels=[NotificationChannel.SLACK],
        )
        assert svc._generate_message_key(message_a) != svc._generate_message_key(message_b)


class TestDataStoreBulkCacheKey:
    """Ensure bulk query cache keys are deterministic and order-independent."""

    def test_bulk_query_cache_key_stable_for_equivalent_pairs(self):
        store = EnhancedMusicDataStore(":memory:")
        pairs_a = [("Track A", "Artist A"), ("Track B", "Artist B")]
        pairs_b = [("Track B", "Artist B"), ("Track A", "Artist A")]
        expected_key = "tracks_bulk:" + hashlib.sha256(
            json.dumps(sorted(pairs_a), ensure_ascii=True).encode("utf-8")
        ).hexdigest()

        with patch.object(store._cache, "set") as cache_set_mock:
            store.get_tracks_with_artists_bulk(pairs_a)
            store.get_tracks_with_artists_bulk(pairs_b)

        created_keys = [call.args[0] for call in cache_set_mock.call_args_list]
        assert created_keys
        assert set(created_keys) == {expected_key}
