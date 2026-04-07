"""Security hardening regression tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.data_store import EnhancedMusicDataStore
from core.notification_service import EnhancedNotificationService, NotificationMessage, NotificationPriority


def test_message_key_is_stable_and_deterministic():
    svc = EnhancedNotificationService()
    msg = NotificationMessage(
        title="same-title",
        content="same-content",
        priority=NotificationPriority.HIGH,
        channels=[],
    )

    first = svc._generate_message_key(msg)
    second = svc._generate_message_key(msg)

    assert first == second


def test_bulk_track_cache_key_is_stable_across_processes():
    store = EnhancedMusicDataStore(":memory:")
    pairs = [("Song A", "Artist A"), ("Song B", "Artist B")]

    key1 = store._build_tracks_bulk_cache_key(pairs)
    key2 = store._build_tracks_bulk_cache_key(list(reversed(pairs)))

    assert key1 == key2
    assert key1.startswith("tracks_bulk:")
    # sha256 hex digest length
    assert len(key1.split("tracks_bulk:")[1]) == 64


@pytest.mark.asyncio
async def test_webhook_post_disables_redirects():
    svc = EnhancedNotificationService()

    fake_response = AsyncMock()
    fake_response.__aenter__.return_value.status = 302
    fake_response.__aenter__.return_value.text = AsyncMock(return_value="redirect")
    fake_response.__aexit__.return_value = None

    fake_session = AsyncMock()
    fake_session.__aenter__.return_value.post.return_value = fake_response
    fake_session.__aexit__.return_value = None

    with (
        patch.object(svc, "_validate_webhook_url", return_value="https://example.com/hook"),
        patch("core.notification_service.aiohttp.ClientSession", return_value=fake_session),
    ):
        with pytest.raises(ValueError, match="redirects are not allowed"):
            await svc._post_json_with_ssrf_protection(
                "https://example.com/hook",
                {"ok": True},
                allow_private=False,
            )
