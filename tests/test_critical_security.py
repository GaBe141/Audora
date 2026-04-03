"""Regression tests for critical security hardening changes."""

from pathlib import Path

import pytest

from core.caching import CacheManager, LocalCacheBackend


class TestCacheKeyHashing:
    """Ensure cache key derivation avoids weak hashing."""

    def test_cache_key_uses_sha256_digest_length(self):
        cache = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
        key = cache._build_cache_key("prefix", ("arg",), {"x": "y"})

        parts = key.split(":")
        assert len(parts) == 3
        # SHA-256 hex digest length is 64, MD5 is 32.
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64


class TestDataStoreTableValidation:
    """Ensure dynamic SQL table names remain strictly whitelisted."""

    def test_export_to_csv_rejects_injected_table_name(self, data_store, tmp_path):
        output_path = tmp_path / "out.csv"
        with pytest.raises(ValueError, match="Invalid table name"):
            data_store.export_to_csv("trends; DROP TABLE trends;--", str(output_path))

    def test_validate_table_name_trims_and_accepts_known_table(self, data_store):
        assert data_store._validate_table_name(" trends ") == "trends"


class TestGitignoreSecurityRules:
    """Ensure credential-bearing generated files are ignored."""

    def test_social_api_config_is_gitignored(self):
        repo_root = Path(__file__).resolve().parent.parent
        content = (repo_root / ".gitignore").read_text(encoding="utf-8")
        assert "config/social_apis.json" in content
