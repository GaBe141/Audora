"""Additional security hardening tests."""

from pathlib import Path
from unittest.mock import patch

from core.data_store import EnhancedMusicDataStore
from scripts.fix_linting_issues import run_command


class TestCommandExecutionHardening:
    """Ensure automation command helper does not execute via shell."""

    def test_run_command_uses_argument_list_without_shell(self):
        with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert run_command(["python3", "--version"], "Version check") is True
            _, kwargs = mock_run.call_args
            assert kwargs.get("check") is True
            assert kwargs.get("capture_output") is True
            assert kwargs.get("text") is True
            assert "shell" not in kwargs


class TestDataStoreCacheKeyHardening:
    """Ensure cache keys are deterministic and not Python-hash based."""

    def test_bulk_track_cache_key_uses_stable_sha256_material(self, tmp_path):
        db_path = tmp_path / "security_cache_key_test.db"
        store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
        pairs = [("Song A", "Artist A"), ("Song B", "Artist B")]

        # First call populates cache; second call should hit identical key material.
        store.get_tracks_with_artists_bulk(pairs)
        store.get_tracks_with_artists_bulk(list(reversed(pairs)))

        # Verify cache entries are namespaced and deterministic style (prefix + hex digest).
        cache_backend = store._cache._backend
        if hasattr(cache_backend, "_cache"):
            cache_keys = list(cache_backend._cache.keys())
            matching = [k for k in cache_keys if "tracks_bulk:" in k]
            assert matching, "Expected tracks_bulk cache key to be created"
            last_key = matching[-1]
            digest = last_key.rsplit("tracks_bulk:", 1)[-1]
            assert len(digest) == 64
            assert all(ch in "0123456789abcdef" for ch in digest.lower())

