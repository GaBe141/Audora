"""Security hardening tests for path safety and cache deserialization."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest

from core.caching import REDIS_AVAILABLE, RedisCacheBackend
from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import resolve_path_within_base, write_json
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


class TestPathSafety:
    """Ensure write paths are constrained to trusted directories."""

    def test_resolve_path_within_base_rejects_traversal(self, tmp_path: Path):
        base_dir = tmp_path / "data"
        base_dir.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="Unsafe path outside base directory"):
            resolve_path_within_base("../etc/passwd", base_dir=base_dir)

    def test_write_json_with_base_dir_rejects_traversal(self, tmp_path: Path):
        base_dir = tmp_path / "data"
        base_dir.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="Unsafe path outside base directory"):
            write_json("../evil.json", {"ok": False}, base_dir=base_dir)

    def test_main_app_report_rejects_outside_data_dir(self):
        app = ComprehensiveMusicDiscoveryApp()
        with pytest.raises(ValueError, match="Unsafe path outside base directory"):
            app.save_discovery_report({"status": "ok"}, custom_filename="../outside.json")

    def test_social_engine_report_rejects_outside_data_dir(self):
        engine = SocialMusicDiscoveryEngine(config={})
        with pytest.raises(ValueError, match="Unsafe path outside base directory"):
            engine.save_discovery_report({"status": "ok"}, filepath="../outside.json")


@pytest.mark.skipif(not REDIS_AVAILABLE, reason="redis package not installed")
class TestRedisCacheSafety:
    """Ensure Redis cache does not deserialize pickle by default."""

    def _signed_envelope(
        self, signing_key: bytes, payload: bytes, version: int, fmt: str | None = None
    ) -> bytes:
        signature = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
        envelope = {
            "v": version,
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if fmt is not None:
            envelope["fmt"] = fmt
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def test_deserialize_rejects_signed_pickle_when_disabled(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AUDORA_CACHE_ALLOW_PICKLE", raising=False)
        monkeypatch.setenv("AUDORA_CACHE_SIGNING_KEY", "test-signing-key")

        backend = object.__new__(RedisCacheBackend)
        backend._signing_key = os.environ["AUDORA_CACHE_SIGNING_KEY"].encode("utf-8")
        backend._allow_pickle = False

        # Minimal pickle payload for integer 42.
        payload = b"\x80\x04K*."
        envelope = self._signed_envelope(backend._signing_key, payload, version=1)
        assert backend._deserialize(envelope) is None

    def test_deserialize_allows_signed_json(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AUDORA_CACHE_ALLOW_PICKLE", raising=False)
        monkeypatch.setenv("AUDORA_CACHE_SIGNING_KEY", "test-signing-key")

        backend = object.__new__(RedisCacheBackend)
        backend._signing_key = os.environ["AUDORA_CACHE_SIGNING_KEY"].encode("utf-8")
        backend._allow_pickle = False

        payload = b'{"hello":"world"}'
        envelope = self._signed_envelope(backend._signing_key, payload, version=2, fmt="json")
        assert backend._deserialize(envelope) == {"hello": "world"}
