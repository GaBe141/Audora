"""Regression tests for security hardening changes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from core.caching import CacheManager, RedisCacheBackend
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def test_notification_message_key_uses_stable_sha256() -> None:
    """Message dedupe keys should be deterministic across runs."""
    service = EnhancedNotificationService()
    message = NotificationMessage(
        title="High signal",
        content="Track signal is above threshold",
        priority=NotificationPriority.HIGH,
        channels=[NotificationChannel.CONSOLE],
    )
    expected = hashlib.sha256(
        f"{message.title}:{message.content[:100]}:{message.priority.value}".encode("utf-8")
    ).hexdigest()
    assert service._generate_message_key(message) == expected


def test_cache_key_builder_uses_sha256_not_md5(mock_cache: CacheManager) -> None:
    """Cache keys should use stronger hashing than MD5."""
    key = mock_cache._build_cache_key("prefix", args=(1, "x"), kwargs={"foo": "bar"})
    parts = key.split(":")
    assert parts[0] == "prefix"
    assert len(parts) == 3
    assert all(len(part) == 64 for part in parts[1:])  # sha256 hex digest length


def test_redis_deserialize_rejects_oversized_payload() -> None:
    """Oversized cache payloads must be rejected before unpickling."""
    backend = object.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    backend._max_payload_bytes = 4

    huge_payload = b"a" * 10
    # Build a correctly signed envelope whose payload still exceeds the limit.
    sig = hmac.new(backend._signing_key, huge_payload, hashlib.sha256).hexdigest()
    envelope = {
        "v": 1,
        "alg": "HMAC-SHA256",
        "sig": sig,
        "payload": base64.b64encode(huge_payload).decode("ascii"),
    }
    raw = json.dumps(envelope).encode("utf-8")

    assert backend._deserialize(raw) is None


def test_redis_deserialize_rejects_oversized_envelope() -> None:
    """Oversized envelopes should be dropped before JSON parsing."""
    backend = object.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    backend._max_payload_bytes = 8

    oversized = b"x" * 5000
    assert backend._deserialize(oversized) is None

