"""Regression tests for Redis cache serialization safety."""

import json
import pickle
from unittest.mock import MagicMock

import pandas as pd
import pytest

from core.caching import RedisCacheBackend


def _backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._client = MagicMock()
    backend._password = None
    return backend


class TestRedisJsonSerialization:
    def test_roundtrip_json_value(self):
        backend = _backend()
        original = {"track": "Song", "score": 91.5, "tags": ["pop"]}
        restored = backend._deserialize(backend._serialize(original))
        assert restored == original

    def test_roundtrip_bytes(self):
        backend = _backend()
        original = b"\x00secret-bytes\xff"
        restored = backend._deserialize(backend._serialize(original))
        assert restored == original

    def test_roundtrip_dataframe(self):
        backend = _backend()
        original = pd.DataFrame({"track": ["A"], "score": [88.0]})
        restored = backend._deserialize(backend._serialize(original))
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(original, restored)

    def test_rejects_pickle_payload(self):
        backend = _backend()
        raw = pickle.dumps({"owned": True})
        assert backend._deserialize(raw) is None

    def test_rejects_legacy_unsigned_json(self):
        backend = _backend()
        raw = json.dumps({"v": 1, "payload": {"x": 1}}).encode("utf-8")
        assert backend._deserialize(raw) is None

    def test_rejects_tampered_signature(self):
        backend = _backend()
        envelope = json.loads(backend._serialize({"ok": True}))
        envelope["sig"] = "0" * 64
        assert backend._deserialize(json.dumps(envelope).encode("utf-8")) is None

    def test_unsupported_object_raises(self):
        backend = _backend()

        class Custom:
            pass

        with pytest.raises(TypeError, match="Unsupported cache value type"):
            backend._serialize(Custom())

    def test_get_deletes_invalid_payload(self):
        backend = _backend()
        backend._client.get.return_value = pickle.dumps({"evil": True})
        assert backend.get("audora:bad") is None
        backend._client.delete.assert_called_once_with("audora:bad")
