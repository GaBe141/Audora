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


def test_logging_file_output_rejects_outside_directory(tmp_path):
    from core.logging_config import setup_logging

    with pytest.raises(ValueError):
        setup_logging(
            log_dir=str(tmp_path),
            app_name="audora",
            console_output=False,
            file_output=True,
        )
