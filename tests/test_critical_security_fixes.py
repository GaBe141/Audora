"""Regression tests for critical security hardening."""

import json
import sys
from unittest.mock import MagicMock

import pandas as pd

from core.caching import RedisCacheBackend

# lastfm_integration imports .config; provide a minimal mock for tests
if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from integrations.lastfm_integration import BASE_URL


class TestLastFmTransportSecurity:
    """Ensure Last.fm client uses encrypted transport."""

    def test_lastfm_base_url_uses_https(self):
        assert BASE_URL.startswith("https://")


class TestRedisCacheSafeSerialization:
    """Ensure Redis payload codec is non-executable and supports key cache types."""

    def _build_backend_without_redis(self) -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"unit-test-signing-key"
        return backend

    def test_round_trip_dict_list_tuple_and_primitives(self):
        backend = self._build_backend_without_redis()
        source = {
            "ok": True,
            "count": 3,
            "name": "audora",
            "nested": {"values": [1, 2, 3], "coords": (10, 20)},
            "none": None,
        }

        serialized = backend._serialize(source)
        restored = backend._deserialize(serialized)
        assert restored == source

    def test_round_trip_dataframe(self):
        backend = self._build_backend_without_redis()
        frame = pd.DataFrame(
            [
                {"track": "Song A", "score": 82.5},
                {"track": "Song B", "score": 91.0},
            ]
        )

        serialized = backend._serialize(frame)
        restored = backend._deserialize(serialized)

        assert isinstance(restored, pd.DataFrame)
        assert restored.to_dict(orient="records") == frame.to_dict(orient="records")

    def test_rejects_legacy_or_malformed_envelope(self):
        backend = self._build_backend_without_redis()
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": "invalid",
            "payload": "legacy",
        }
        assert backend._deserialize(json.dumps(envelope).encode("utf-8")) is None
