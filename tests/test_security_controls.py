"""Tests for cache signing, path confinement, and CSV formula neutralization."""

from pathlib import Path

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.data_store import database_path_from_config
from core.utils import (
    PROJECT_ROOT,
    confine_child_path,
    neutralize_csv_frame,
    resolve_within_project,
)
from integrations.extended_platforms import safe_path_segment
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import chart_url


class TestSignedJsonCache:
    """Redis cache entries are signed JSON and are never unpickled."""

    def _backend(self) -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"unit-test-key"
        return backend

    def test_round_trip_json(self):
        backend = self._backend()
        raw = backend._serialize({"score": 1, "title": "safe"})
        assert b"pickle" not in raw
        assert backend._deserialize(raw) == {"score": 1, "title": "safe"}

    def test_rejects_tampered_envelope(self):
        backend = self._backend()
        raw = backend._serialize({"score": 1})
        tampered = raw.replace(b"HMAC-SHA256", b"HMAC-SHA255")
        assert backend._deserialize(tampered) is None


class TestPathConfinement:
    """Project file helpers reject traversal and symlinks."""

    def test_relative_database_path_stays_in_project(self):
        resolved = Path(database_path_from_config("data/enhanced_music_trends.db"))
        assert resolved == (PROJECT_ROOT / "data" / "enhanced_music_trends.db").resolve()

    def test_rejects_parent_escape(self):
        with pytest.raises(ValueError):
            resolve_within_project("../../etc/passwd")

    def test_rejects_absolute_secret_path(self):
        with pytest.raises(ValueError):
            database_path_from_config("/etc/passwd")

    def test_rejects_memory_database_from_config(self):
        with pytest.raises(ValueError):
            database_path_from_config(":memory:")

    def test_child_name_rejects_traversal(self):
        with pytest.raises(ValueError):
            confine_child_path(PROJECT_ROOT / "data", "../.env")

    def test_database_file_mode_is_private(self, tmp_path):
        from core.data_store import EnhancedMusicDataStore

        db_path = tmp_path / "private.db"
        store = EnhancedMusicDataStore(str(db_path), backup_dir=str(tmp_path / "backups"))
        store.close_pool()
        assert db_path.stat().st_mode & 0o777 == 0o600

    def test_symlinked_database_is_rejected(self, tmp_path):
        from core.data_store import EnhancedMusicDataStore

        target = tmp_path / "target.db"
        target.write_text("", encoding="utf-8")
        link = tmp_path / "link.db"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="Symlinked"):
            EnhancedMusicDataStore(str(link), backup_dir=str(tmp_path / "backups"))


class TestCsvNeutralization:
    """Spreadsheet formulas are prefixed in every column."""

    def test_prefixes_formula_text_and_keeps_numbers(self):
        frame = pd.DataFrame(
            {
                "command": ["=1+1", " =1+1", "\t@cmd", "safe"],
                "score": [1, 2, 3, 4],
            }
        )
        neutralized = neutralize_csv_frame(frame)
        assert neutralized["command"].tolist() == ["'=1+1", "' =1+1", "'\t@cmd", "safe"]
        assert neutralized["score"].tolist() == [1, 2, 3, 4]


def test_chart_url_rejects_host_injection():
    assert chart_url("regional", "global", "2024-01-02") is not None
    assert chart_url("regional", "US", "2024-01-02") is not None
    assert chart_url("regional", "../@127.0.0.1", "2024-01-02") is None
    assert chart_url("regional", "us", "2024-99-99") is None
    assert chart_url("viral", "https://evil.test", "2024-01-02") is None


def test_safe_path_segment_rejects_traversal():
    assert safe_path_segment("hiphopheads") == "hiphopheads"
    assert safe_path_segment("123456789012345678") == "123456789012345678"
    assert safe_path_segment("../users/@me") is None
    assert safe_path_segment("blog.example.com") is None
    assert safe_path_segment("a/b") is None


def test_musicbrainz_rejects_mbid_path_injection():
    api = MusicBrainzAPI()
    assert api.get_artist_details("../secret") is None
    assert api.get_artist_details("not-a-uuid") is None


def test_credentialed_social_session_ignores_proxy_env():
    import asyncio

    from integrations.social_discovery_engine import credentialed_session

    async def _check() -> None:
        async with credentialed_session() as session:
            assert session.trust_env is False

    asyncio.run(_check())


def test_lastfm_session_ignores_proxy_env():
    from integrations.lastfm_integration import LastFmAPI

    api = LastFmAPI(api_key="a" * 32)
    assert api.session.trust_env is False


def test_logging_file_output_rejects_outside_directory(tmp_path):
    from core.logging_config import setup_logging

    with pytest.raises(ValueError):
        setup_logging(
            log_dir=str(tmp_path),
            app_name="audora",
            console_output=False,
            file_output=True,
        )
