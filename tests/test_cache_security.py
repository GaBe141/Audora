"""Security tests for Redis cache serialization (no pickle RCE)."""

import base64
import hashlib
import hmac
import json
import pickle
from pathlib import Path

import pandas as pd

from core.caching import deserialize_cache_value, serialize_cache_value

SIGNING_KEY = b"unit-test-cache-signing-key"


class TestJsonCacheEnvelopes:
    """Cache payloads must be signed JSON, never pickle."""

    def test_roundtrip_json_values(self):
        payload = serialize_cache_value({"track": "Song", "score": 91}, SIGNING_KEY)
        assert deserialize_cache_value(payload, SIGNING_KEY) == {"track": "Song", "score": 91}

    def test_roundtrip_bytes_and_dataframe(self):
        raw = serialize_cache_value(b"binary-cache", SIGNING_KEY)
        assert deserialize_cache_value(raw, SIGNING_KEY) == b"binary-cache"

        frame = pd.DataFrame([{"track": "A", "score": 10}])
        encoded = serialize_cache_value(frame, SIGNING_KEY)
        decoded = deserialize_cache_value(encoded, SIGNING_KEY)
        assert isinstance(decoded, pd.DataFrame)
        assert list(decoded["track"]) == ["A"]

    def test_rejects_unsigned_pickle_payload(self):
        pickle_blob = pickle.dumps({"owned": True})
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": "00",
                "payload": base64.b64encode(pickle_blob).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_value(envelope, SIGNING_KEY) is None

    def test_rejects_signed_legacy_pickle_envelope(self):
        pickle_blob = pickle.dumps({"owned": True})
        signature = hmac.new(SIGNING_KEY, pickle_blob, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickle_blob).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_value(envelope, SIGNING_KEY) is None

    def test_rejects_tampered_signature(self):
        payload = serialize_cache_value("ok", SIGNING_KEY)
        envelope = json.loads(payload.decode("utf-8"))
        envelope["sig"] = "0" * 64
        assert deserialize_cache_value(json.dumps(envelope).encode("utf-8"), SIGNING_KEY) is None

    def test_sha256_used_for_cache_keys(self):
        from core.caching import CacheManager, LocalCacheBackend

        manager = CacheManager(backend=LocalCacheBackend(), key_prefix="t")
        key = manager._build_cache_key("fn", (1,), {"b": 2})
        assert len(key.split(":")[-1]) == 64
        source = Path("core/caching.py").read_text(encoding="utf-8")
        assert "pickle.loads" not in source
        assert "md5(" not in source
