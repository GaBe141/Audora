"""Tests for critical cache, path, and outbound request hardening."""

import json

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.data_store import EnhancedMusicDataStore, database_path_from_config
from core.utils import neutralize_csv_frame, neutralize_csv_value
from integrations.extended_platforms import safe_path_segment
from integrations.lastfm_integration import BASE_URL
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import SpotifyChartsAPI


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
