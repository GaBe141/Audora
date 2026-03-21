"""Regression tests for security hardening updates."""

from pathlib import Path

import pytest

from core.caching import CacheManager, LocalCacheBackend
from core.main_app import ComprehensiveMusicDiscoveryApp
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


def _build_minimal_app(tmp_path: Path) -> ComprehensiveMusicDiscoveryApp:
    """Create app instance without running full initialization."""
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    app.reports_dir = (tmp_path / "reports").resolve()
    app.reports_dir.mkdir(parents=True, exist_ok=True)
    return app


def test_save_discovery_report_rejects_traversal_paths(tmp_path: Path):
    app = _build_minimal_app(tmp_path)
    with pytest.raises(ValueError, match="path separators"):
        app.save_discovery_report({"status": "ok"}, "../escape.json")


def test_save_discovery_report_uses_safe_directory(tmp_path: Path):
    app = _build_minimal_app(tmp_path)
    saved_path = Path(app.save_discovery_report({"status": "ok"}, "weekly_report")).resolve()
    assert saved_path.exists()
    assert saved_path.name == "weekly_report.json"
    assert saved_path.is_relative_to(app.reports_dir)


def test_notification_message_key_uses_stable_sha256():
    svc = EnhancedNotificationService.__new__(EnhancedNotificationService)
    message = NotificationMessage(
        title="Security Test",
        content="This message verifies deterministic hashing.",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.CONSOLE],
    )
    key1 = svc._generate_message_key(message)
    key2 = svc._generate_message_key(message)
    digest, priority = key1.split(":")
    assert key1 == key2
    assert len(digest) == 64
    assert priority == NotificationPriority.LOW.value


def test_cache_manager_build_key_uses_sha256_digests():
    cache = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
    key = cache._build_cache_key("fn", (1, "two"), {"alpha": 3})
    parts = key.split(":")
    assert len(parts) == 3
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64
