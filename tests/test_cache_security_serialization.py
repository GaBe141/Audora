"""Security-focused tests for Redis cache serialization helpers."""

from dataclasses import dataclass

import pytest

from core.caching import (
    REDIS_SERIALIZATION_PREFIX,
    _deserialize_cache_value,
    _serialize_cache_value,
)


def test_safe_json_roundtrip() -> None:
    value = {"track": "Song", "score": 97, "platforms": ["spotify", "tiktok"]}
    encoded = _serialize_cache_value(value)
    assert isinstance(encoded, bytes)
    assert encoded.startswith(REDIS_SERIALIZATION_PREFIX)
    assert _deserialize_cache_value(encoded) == value


def test_reject_legacy_unsafe_payload() -> None:
    with pytest.raises(ValueError, match="Unsupported cache serialization format"):
        _deserialize_cache_value(b"legacy-pickle-bytes")


@dataclass
class _UnserializableObject:
    name: str


def test_skip_unsupported_types() -> None:
    # Should refuse to serialize unknown object types instead of using pickle.
    assert _serialize_cache_value(_UnserializableObject(name="unsafe")) is None
