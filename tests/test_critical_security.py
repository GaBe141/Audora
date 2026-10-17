"""Tests for critical cache, path, and outbound request hardening."""

import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.config import SecureConfig
from core.data_store import EnhancedMusicDataStore, database_path_from_config
from core.logging_config import NofollowFileHandler, safe_log_filename, safe_log_level
from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import neutralize_csv_frame, neutralize_csv_value, save_dataframe
from integrations.api_config import SocialAPIManager
from integrations.extended_platforms import safe_path_segment
from integrations.lastfm_integration import BASE_URL
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine
from integrations.spotify_charts_integration import SpotifyChartsAPI


def test_spotify_redirect_uri_requires_exact_loopback(monkeypatch):
    config = SecureConfig.__new__(SecureConfig)
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
    assert config.get_spotify_config()["redirect_uri"] == "http://127.0.0.1:8888/callback"
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://localhost:8080/callback")
    assert config.get_spotify_config()["redirect_uri"] == "http://localhost:8080/callback"

    blocked = (
        "http://localhost.evil.com/callback",
        "http://127.0.0.1.evil.com/callback",
        "http://127.0.0.1@evil.com/callback",
        "http://user:pass@localhost/callback",
        "https://localhost/callback",
        "http://2130706433/callback",
        "http://127.1/callback",
        "http://0x7f.0.0.1/callback",
    )
    for redirect_uri in blocked:
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", redirect_uri)
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            config.get_spotify_config()


def test_social_api_secrets_stay_private_and_inside_project(tmp_path, monkeypatch):
    monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
    with pytest.raises(ValueError, match="relative|escapes"):
        SocialAPIManager("/tmp/social_apis.json")
    with pytest.raises(ValueError, match="relative|escapes"):
        SocialAPIManager("../social_apis.json")

    manager = SocialAPIManager("config/social_apis.json")
    secret_file = tmp_path / "config" / "social_apis.json"
    assert secret_file.stat().st_mode & 0o777 == 0o600

    outside = tmp_path / "outside.json"
    outside.write_text("keep\n", encoding="utf-8")
    outside.chmod(0o644)
    secret_file.unlink()
    secret_file.symlink_to(outside)
    with pytest.raises(OSError, match="symlink"):
        manager.set_api_key("youtube", "super-secret-key")
    assert outside.read_text(encoding="utf-8") == "keep\n"
    assert outside.stat().st_mode & 0o777 == 0o644


def test_log_files_reject_symlink_and_traversal(tmp_path):
    assert safe_log_level("DEBUG") == 10
    assert safe_log_level("Logger") == 20
    assert safe_log_level(None) == 20
    assert safe_log_filename("../../etc/passwd") == "passwd"
    assert safe_log_filename("..") == "audora"
    assert safe_log_filename("audora_test") == "audora_test"

    outside = tmp_path / "outside.log"
    outside.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "app.log"
    link.symlink_to(outside)
    with pytest.raises(OSError, match="symlink"):
        NofollowFileHandler(link)
    assert outside.read_text(encoding="utf-8") == "keep\n"

    log_file = tmp_path / "plain.log"
    handler = NofollowFileHandler(log_file, encoding="utf-8")
    handler.close()
    assert log_file.stat().st_mode & 0o777 == 0o600


def test_redis_cache_uses_signed_json_not_pickle():
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    payload = backend._serialize({"track": "safe", "score": 1})
    envelope = json.loads(payload.decode("utf-8"))
    assert envelope["v"] == 2
    assert b"pickle" not in payload
    assert backend._deserialize(payload) == {"track": "safe", "score": 1}

    tampered = json.loads(payload.decode("utf-8"))
    tampered["sig"] = "0" * 64
    assert backend._deserialize(json.dumps(tampered).encode("utf-8")) is None


def test_neutralize_csv_formula_prefixes():
    frame = pd.DataFrame(
        {
            "formula": pd.Series(["=1+1", " =1+1", "\t@cmd"], dtype="string"),
            "score": [1, 2, 3],
        }
    )
    neutralized = neutralize_csv_frame(frame)
    assert neutralized["formula"].tolist() == ["'=1+1", "' =1+1", "'\t@cmd"]
    assert neutralized["score"].tolist() == [1, 2, 3]
    assert neutralize_csv_value("plain") == "plain"


def test_database_path_from_config_rejects_absolute_path():
    with pytest.raises(ValueError, match="relative"):
        database_path_from_config("/tmp/audora.db")


def test_memory_database_and_symlink_rejection(tmp_path):
    store = EnhancedMusicDataStore(db_path=":memory:", backup_dir=str(tmp_path / "backups"))
    assert store.db_path == ":memory:"
    store.close_pool()

    target = tmp_path / "real.db"
    target.touch()
    link = tmp_path / "link.db"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        EnhancedMusicDataStore(db_path=str(link), backup_dir=str(tmp_path / "backups"))


def test_spotify_chart_url_allowlists_country_and_date():
    api = SpotifyChartsAPI()
    url = api.chart_url("regional", "US", "2024-01-02")
    assert url.endswith("/regional-us-daily/2024-01-02")
    with pytest.raises(ValueError):
        api.chart_url("regional", "../etc", "2024-01-02")
    with pytest.raises(ValueError):
        api.chart_url("regional", "us", "2024-02-31")


def test_musicbrainz_detail_requires_uuid():
    api = MusicBrainzAPI()
    assert api.get_artist_details("../admin") is None
    assert api.get_artist_releases("not-a-uuid") == []
    assert api.get_related_artists("123") == []


def test_safe_path_segment_rejects_traversal():
    assert safe_path_segment("hiphopheads", label="subreddit") == "hiphopheads"
    with pytest.raises(ValueError):
        safe_path_segment("../etc", label="subreddit")


def test_lastfm_uses_https():
    assert BASE_URL.startswith("https://")


def test_save_dataframe_refuses_symlink(tmp_path):
    target = tmp_path / "outside.csv"
    target.write_text("secret\n", encoding="utf-8")
    link = tmp_path / "export.csv"
    link.symlink_to(target)
    frame = pd.DataFrame({"artist": ["Artist A"]})
    with pytest.raises(OSError, match="symlink"):
        save_dataframe(frame, link, create_dirs=False)
    assert target.read_text(encoding="utf-8") == "secret\n"


def test_discovery_reports_stay_inside_project():
    engine = SocialMusicDiscoveryEngine({})
    with pytest.raises(ValueError, match="relative|escapes"):
        engine.save_discovery_report({"ok": True}, filepath="../.env")

    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="relative|escapes"):
        app.save_discovery_report({"ok": True}, custom_filename="/tmp/audora-report.json")


def test_database_files_and_backup_are_private(tmp_path, monkeypatch):
    old_umask = os.umask(0o022)
    try:
        db_path = tmp_path / "trends.db"
        store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
        assert db_path.stat().st_mode & 0o777 == 0o600
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{db_path}{suffix}")
            if sidecar.exists():
                assert sidecar.stat().st_mode & 0o777 == 0o600

        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 1, 1, 0, 0, 0)

        monkeypatch.setattr("core.data_store.datetime", FrozenDateTime)
        planted = tmp_path / "backups" / "music_trends_backup_20260101_000000.db"
        planted.symlink_to(tmp_path / "outside.db")
        with pytest.raises(ValueError, match="backup"):
            store.create_backup()
        planted.unlink()

        backup = Path(store.create_backup())
        assert backup.stat().st_mode & 0o777 == 0o600
        store.close_pool()
    finally:
        os.umask(old_umask)
