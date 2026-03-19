"""Security-focused tests for Redis cache serialization."""

import pytest

from core.caching import RedisCacheBackend

pd = pytest.importorskip("pandas")


class TestRedisCacheSerialization:
    """Ensure Redis cache payloads are safely serialized/deserialized."""

    @staticmethod
    def _backend() -> RedisCacheBackend:
        # Bypass network setup; these tests only validate serialization helpers.
        return RedisCacheBackend.__new__(RedisCacheBackend)

    def test_json_payload_round_trip(self):
        backend = self._backend()
        value = {"a": 1, "b": ["x", 2, True]}

        encoded = backend._serialize_for_redis(value)
        decoded = backend._deserialize_for_redis(encoded)

        assert decoded == value

    def test_bytes_payload_round_trip(self):
        backend = self._backend()
        value = b"\x01\x02secure-binary"

        encoded = backend._serialize_for_redis(value)
        decoded = backend._deserialize_for_redis(encoded)

        assert decoded == value

    def test_dataframe_payload_round_trip(self):
        backend = self._backend()
        value = pd.DataFrame({"track": ["A", "B"], "score": [91.5, 88.2]})

        encoded = backend._serialize_for_redis(value)
        decoded = backend._deserialize_for_redis(encoded)

        assert decoded.equals(value)

    def test_unsupported_payload_type_raises(self):
        backend = self._backend()

        class Unsupported:
            pass

        with pytest.raises(TypeError):
            backend._serialize_for_redis(Unsupported())

    def test_invalid_non_json_payload_rejected(self):
        backend = self._backend()

        with pytest.raises(ValueError):
            backend._deserialize_for_redis(b"\x80\x04malicious-pickle")
