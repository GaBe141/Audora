"""Security-focused tests for Redis cache serialization."""

import pytest

from core.caching import _deserialize_from_redis, _serialize_for_redis


def test_redis_serialization_roundtrip_json_payload():
    value = {"track": "Example", "score": 91.2, "tags": ["viral", "test"]}
    payload = _serialize_for_redis(value)
    assert _deserialize_from_redis(payload) == value


def test_redis_serialization_roundtrip_bytes_payload():
    value = b"\x01\x02cache-bytes"
    payload = _serialize_for_redis(value)
    assert _deserialize_from_redis(payload) == value


def test_redis_deserialization_rejects_non_json_payload():
    # Simulates legacy/unsafe binary payloads (e.g., raw pickle bytes).
    with pytest.raises(ValueError, match="not valid UTF-8 JSON|not valid JSON"):
        _deserialize_from_redis(b"\x80\x04\x95unsafe")


def test_redis_serialization_raises_for_unsupported_objects():
    class UnsupportedValue:
        pass

    with pytest.raises(TypeError, match="not JSON serializable"):
        _serialize_for_redis(UnsupportedValue())


def test_redis_serialization_roundtrip_pandas_dataframe():
    pandas = pytest.importorskip("pandas")
    df = pandas.DataFrame(
        [
            {"track_name": "Song A", "score": 90.0},
            {"track_name": "Song B", "score": 84.5},
        ]
    )
    payload = _serialize_for_redis(df)
    restored = _deserialize_from_redis(payload)
    assert restored.to_dict("records") == df.to_dict("records")
