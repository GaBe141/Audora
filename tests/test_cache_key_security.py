"""Security-focused tests for deterministic, stable cache/message keys."""

from core.caching import CacheManager, LocalCacheBackend
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def test_cache_key_builder_is_deterministic_across_instances():
    backend1 = LocalCacheBackend(max_size=10)
    backend2 = LocalCacheBackend(max_size=10)
    cache1 = CacheManager(backend=backend1, key_prefix="audora_test")
    cache2 = CacheManager(backend=backend2, key_prefix="audora_test")

    key1 = cache1._build_cache_key("prefix", (1, "a"), {"x": 2})
    key2 = cache2._build_cache_key("prefix", (1, "a"), {"x": 2})

    assert key1 == key2


def test_notification_message_key_is_deterministic():
    svc = EnhancedNotificationService()
    msg = NotificationMessage(
        title="Same Title",
        content="Same body content",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.CONSOLE],
    )

    key1 = svc._generate_message_key(msg)
    key2 = svc._generate_message_key(msg)

    assert key1 == key2
