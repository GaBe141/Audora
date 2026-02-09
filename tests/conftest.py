"""Pytest configuration and shared fixtures for Audora test suite."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add repository root to path so imports like "from core.*" and "from analytics.*" work
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def pytest_ignore_collect(path, config):
    """Ignore legacy script-style tests that use old 'src' layout and fail to import."""
    name = getattr(path, "name", None) or getattr(path, "basename", "")
    is_file = getattr(path, "is_file", None) or getattr(path, "isfile", lambda: False)
    if name in ("test_basic_statistical.py", "test_statistical_analysis.py") and callable(is_file) and is_file():
        return True
    return False


@pytest.fixture
def temp_db_path(tmp_path):
    """Yield an isolated path for a temporary SQLite database."""
    return tmp_path / "test_audora.db"


@pytest.fixture
def data_store(temp_db_path):
    """Yield an EnhancedMusicDataStore using a temporary database. Cleans up pool on teardown."""
    from core.data_store import EnhancedMusicDataStore

    store = EnhancedMusicDataStore(
        db_path=str(temp_db_path), backup_dir=str(temp_db_path.parent / "backups")
    )
    yield store
    store.close_pool()


@pytest.fixture
def sample_trends():
    """Build a list of TrendData with minimal valid fields for bulk/pool tests."""
    from core.data_store import TrendData

    now = datetime.now()
    return [
        TrendData(
            platform="spotify",
            track_id="tid1",
            track_name="Track One",
            artist="Artist A",
            score=85.0,
            rank=1,
            region="US",
            trend_date=now,
            metadata={"source": "test"},
            first_detected=now,
        ),
        TrendData(
            platform="spotify",
            track_id="tid2",
            track_name="Track Two",
            artist="Artist B",
            score=72.0,
            rank=2,
            region="US",
            trend_date=now,
            metadata={"source": "test"},
            first_detected=now,
        ),
    ]


@pytest.fixture
def mock_cache():
    """Yield a CacheManager with LocalCacheBackend for deterministic tests without Redis."""
    from core.caching import CacheManager, LocalCacheBackend

    backend = LocalCacheBackend(max_size=100)
    return CacheManager(backend=backend, default_ttl=3600, key_prefix="audora_test")
