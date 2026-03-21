"""Regression tests for security hardening updates."""

from core.caching import CacheManager, LocalCacheBackend
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def test_notification_message_key_uses_stable_sha256():
    svc = EnhancedNotificationService.__new__(EnhancedNotificationService)
    message = NotificationMessage(
        title="Security Test",
        content="This message verifies deterministic hashing.",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.CONSOLE],
    )
    key1 = svc._generate_message_key(message)
    key2 = svc._generate_message_key(message)
    digest, priority = key1.split(":")
    assert key1 == key2
    assert len(digest) == 64
    assert priority == NotificationPriority.LOW.value


def test_cache_manager_build_key_uses_sha256_digests():
    cache = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
    key = cache._build_cache_key("fn", (1, "two"), {"alpha": 3})
    parts = key.split(":")
    assert len(parts) == 3
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64
