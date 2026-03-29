"""Security tests for OAuth token cache handling."""

from pathlib import Path

import pytest

from core.auth import _secure_cache_file_path


class TestAuthCacheSecurity:
    """Validate OAuth token cache path hardening."""

    def test_creates_file_with_secure_permissions(self, tmp_path):
        cache_file = tmp_path / ".cache"
        resolved = _secure_cache_file_path(cache_file)

        assert resolved == cache_file
        assert resolved.exists()
        assert resolved.is_file()

        if resolved.stat().st_mode:
            assert oct(resolved.stat().st_mode & 0o777) == "0o600"

    def test_uses_file_inside_existing_cache_directory(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()

        resolved = _secure_cache_file_path(cache_dir)
        assert resolved == cache_dir / "spotify_token_cache"
        assert resolved.exists()
        assert resolved.is_file()

    def test_rejects_symlink_cache_target(self, tmp_path):
        target = tmp_path / "real_cache"
        target.touch()
        symlink = tmp_path / ".cache"
        symlink.symlink_to(target)

        with pytest.raises(ValueError, match="symlink"):
            _secure_cache_file_path(symlink)
