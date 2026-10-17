"""Tests for critical cache, redirect, path, and CSV protections."""

import json
from pathlib import Path

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.config import SecureConfig
from core.data_store import EnhancedMusicDataStore, database_path_from_config
from core.utils import neutralize_csv_frame, read_json, write_json


class TestRedirectUri:
    def test_rejects_suffix_and_userinfo_bypasses(self):
        rejected = [
            "http://localhost.evil.com/callback",
            "http://127.0.0.1@evil.com/callback",
            "http://2130706433/callback",
            "http://0177.0.0.1/callback",
            "http://0x7f.0.0.1/callback",
            "http://127.1/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.1:8888/callback\r\nSet-Cookie: x=y",
            "http://127.0.0.1:8888/callback?x=\r\n",
            "http://127.0.0.1#@evil.com/callback",
            "http://127.0.0.1\\@evil.com/callback",
        ]
        for uri in rejected:
            with pytest.raises(ValueError):
                SecureConfig._validate_redirect_uri(uri)

    def test_allows_exact_loopback_http(self):
        SecureConfig._validate_redirect_uri("http://127.0.0.1:8888/callback")
        SecureConfig._validate_redirect_uri("http://localhost:8888/callback")
        SecureConfig._validate_redirect_uri("http://localhost./callback")


class TestCacheEnvelope:
    def test_signed_json_round_trip_rejects_pickle_envelope(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        encoded = backend._serialize({"track": "safe"})
        assert b"pickle" not in encoded
        assert json.loads(encoded)["v"] == 2
        assert backend._deserialize(encoded) == {"track": "safe"}
        forged = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "nope", "payload": "YQ=="}
        ).encode()
        assert backend._deserialize(forged) is None


class TestPathAndCsv:
    def test_database_config_rejects_absolute_and_escape(self, tmp_path):
        with pytest.raises(ValueError):
            database_path_from_config("/tmp/audora.db")
        with pytest.raises(ValueError):
            database_path_from_config("../../etc/passwd")

    def test_database_refuses_symlink(self, tmp_path):
        target = tmp_path / "real.db"
        target.write_bytes(b"")
        link = tmp_path / "link.db"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="symlink"):
            EnhancedMusicDataStore(db_path=str(link), backup_dir=str(tmp_path / "backups"))

    def test_json_helpers_refuse_symlink(self, tmp_path):
        target = tmp_path / "secret.json"
        target.write_text('{"ok": true}', encoding="utf-8")
        link = tmp_path / "link.json"
        link.symlink_to(target)
        with pytest.raises(OSError):
            read_json(link)
        with pytest.raises(ValueError):
            write_json(link, {"no": True})

    def test_csv_formula_neutralization_covers_every_column(self):
        frame = pd.DataFrame(
            [{"formula": "=1+1", "spaced": " =1+1", "tabbed": "\t@cmd", "safe": "Artist A"}]
        )
        neutralized = neutralize_csv_frame(frame)
        assert neutralized.loc[0, "formula"] == "'=1+1"
        assert neutralized.loc[0, "spaced"] == "' =1+1"
        assert neutralized.loc[0, "tabbed"] == "'\t@cmd"
        assert neutralized.loc[0, "safe"] == "Artist A"


def test_trending_report_stays_inside_project():
    from core.utils import PROJECT_ROOT
    from integrations.spotify_trending import SpotifyTrendingIntegration

    integration = SpotifyTrendingIntegration()
    with pytest.raises(ValueError, match="escapes"):
        integration.create_trending_report("../../outside-audora")
    assert not (PROJECT_ROOT / "../../outside-audora").resolve().exists()


def test_private_database_file_mode(tmp_path):
    db_path = tmp_path / "mode.db"
    store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
    store.close_pool()
    assert Path(store.db_path).stat().st_mode & 0o777 == 0o600
