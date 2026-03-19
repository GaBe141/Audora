"""Security-focused tests for cache serialization/deserialization."""

import json
import pickle

from core.caching import (
    CacheManager,
    LocalCacheBackend,
    _deserialize_signed_cache_value,
    _serialize_signed_cache_value,
)


def test_signed_cache_payload_round_trip() -> None:
    """Signed cache payloads should deserialize back to original value."""
    key = b"unit-test-signing-key"
    value = {"track": "Song A", "score": 97.5, "tags": ["viral", "trending"]}

    payload = _serialize_signed_cache_value(value, key)
    restored = _deserialize_signed_cache_value(payload, key)

    assert restored == value


def test_signed_cache_payload_rejects_tampered_signature() -> None:
    """Tampering signature must invalidate payload before pickle is loaded."""
    key = b"unit-test-signing-key"
    value = {"foo": "bar"}

    payload = _serialize_signed_cache_value(value, key)
    decoded = json.loads(payload.decode("utf-8"))
    decoded["signature"] = "0" * 64
    tampered_payload = json.dumps(decoded).encode("utf-8")

    assert _deserialize_signed_cache_value(tampered_payload, key) is None


def test_signed_cache_payload_rejects_legacy_unsigned_pickle() -> None:
    """Legacy raw pickle bytes are blocked as unsafe unsigned payloads."""
    legacy_payload = pickle.dumps({"legacy": True})

    assert _deserialize_signed_cache_value(legacy_payload, b"any-key") is None


def test_cache_key_builder_uses_strong_hashes() -> None:
    """Cache key components for args/kwargs should be SHA-256 hex digests."""
    manager = CacheManager(backend=LocalCacheBackend(), key_prefix="audora")
    key = manager._build_cache_key("prefix", args=("a", 1), kwargs={"k": "v"})

    parts = key.split(":")
    assert len(parts) == 3
    # SHA-256 digest hex length
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64
