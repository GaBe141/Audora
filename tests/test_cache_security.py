"""Security tests for signed JSON cache payloads."""

import json
import pickle
from datetime import datetime

import pandas as pd
import pytest

from core.caching import dumps_signed, loads_signed


class TestSignedCachePayloads:
    """Redis values must round-trip as signed JSON and reject pickle."""

    def test_round_trip_nested_values(self):
        signing_key = b"k" * 32
        original = {
            "count": 2,
            "when": datetime(2026, 1, 2, 3, 4, 5),
            "pair": ("a", 1),
            "frame": pd.DataFrame({"score": [1, 2]}),
        }
        restored = loads_signed(dumps_signed(original, signing_key), signing_key)
        assert restored["count"] == 2
        assert restored["when"] == original["when"]
        assert restored["pair"] == ("a", 1)
        assert restored["frame"]["score"].tolist() == [1, 2]

    def test_rejects_pickle_payload(self):
        signing_key = b"k" * 32
        pickled = pickle.dumps({"command": "os.system"})
        with pytest.raises(ValueError):
            loads_signed(pickled, signing_key)

    def test_rejects_tampered_signature(self):
        signing_key = b"k" * 32
        envelope = json.loads(dumps_signed({"ok": True}, signing_key))
        envelope["sig"] = "0" * 64
        with pytest.raises(ValueError, match="signature"):
            loads_signed(json.dumps(envelope).encode("utf-8"), signing_key)

    def test_rejects_wrong_key(self):
        raw = dumps_signed({"ok": True}, b"a" * 32)
        with pytest.raises(ValueError, match="signature"):
            loads_signed(raw, b"b" * 32)
