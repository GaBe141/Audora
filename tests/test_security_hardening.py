"""Tests for critical cache, CSV, redirect, and outbound-request hardening."""

import asyncio
import json
from datetime import datetime, timedelta

import pandas as pd
import pytest

from core.auth import spotify_token_cache_path
from core.caching import deserialize_cache_value, serialize_cache_value
from core.config import SecureConfig
from core.data_store import EnhancedMusicDataStore
from core.notification_service import EnhancedNotificationService
from core.utils import neutralize_csv_frame, neutralize_csv_value, project_root
from integrations.extended_platforms import DiscordMusicBot, RedditMusicAPI
from integrations.safe_http import NoRedirectSession


def test_signed_json_cache_round_trips_dataframe_and_rejects_pickle_envelopes():
    signing_key = b"test-signing-key"
    frame = pd.DataFrame([{"artist": "A", "score": 1}])
    raw = serialize_cache_value({"rows": frame, "when": datetime(2026, 1, 2, 3, 4, 5)}, signing_key)
    restored = deserialize_cache_value(raw, signing_key)
    assert restored["when"] == datetime(2026, 1, 2, 3, 4, 5)
    assert restored["rows"].iloc[0]["artist"] == "A"

    tampered = bytearray(raw)
    tampered[-2] ^= 1
    assert deserialize_cache_value(bytes(tampered), signing_key) is None

    pickle_envelope = json.dumps(
        {"v": 1, "alg": "HMAC-SHA256", "sig": "abc", "payload": "cGlja2xl"}
    ).encode()
    assert deserialize_cache_value(pickle_envelope, signing_key) is None


def test_csv_neutralizes_formula_prefixes_and_leading_whitespace():
    assert neutralize_csv_value("=1+1") == "'=1+1"
    assert neutralize_csv_value(" =1+1") == "' =1+1"
    assert neutralize_csv_value("\t@cmd") == "'\t@cmd"
    assert neutralize_csv_value("plain") == "plain"
    assert neutralize_csv_value(5) == 5

    frame = pd.DataFrame([{"artist": "=1+1", "score": 5}, {"artist": " =1+1", "score": 1}])
    neutralized = neutralize_csv_frame(frame)
    exported = neutralized.to_csv(index=False)
    assert "'=1+1" in exported
    assert "' =1+1" in exported
    assert "\n=1+1," not in exported


def test_redirect_uri_requires_exact_loopback_host(monkeypatch, tmp_path):
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://localhost.evil.com/callback")
    config = SecureConfig(env_file=tmp_path / "missing.env")
    with pytest.raises(ValueError, match="Invalid redirect URI"):
        config.get_spotify_config()

    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
    assert (
        SecureConfig(env_file=tmp_path / "missing.env")
        .get_spotify_config()["redirect_uri"]
        .endswith("/callback")
    )


def test_export_path_cannot_leave_project_or_database(temp_db_path):
    store = EnhancedMusicDataStore(
        db_path=str(temp_db_path), backup_dir=str(temp_db_path.parent / "backups")
    )
    with pytest.raises(ValueError, match="allowed directories"):
        store.export_to_csv("trends", "/tmp/audora-escape.csv")
    exported = store.export_to_csv("trends", str(temp_db_path.parent / "trends.csv"))
    assert exported.endswith("trends.csv")
    store.close_pool()


def test_reddit_and_discord_identifiers_are_allowlisted():
    reddit = RedditMusicAPI("client", "secret")
    reddit.access_token = "token"
    reddit.token_expires = datetime.now() + timedelta(hours=1)
    assert asyncio.run(reddit.get_music_subreddit_posts("../admin")) == []

    discord = DiscordMusicBot("bot-token")
    assert asyncio.run(discord.get_guild_voice_activity("../../evil")) == {}


def test_no_redirect_session_is_not_a_client_session_subclass():
    import aiohttp

    assert not issubclass(NoRedirectSession, aiohttp.ClientSession)


def test_notification_config_ignores_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    planted = tmp_path / "config"
    planted.mkdir()
    (planted / "notification_config.json").write_text(
        json.dumps({"email": {"smtp_server": "evil.example", "password": "from-cwd"}}),
        encoding="utf-8",
    )
    service = EnhancedNotificationService()
    assert service.config["email"]["smtp_server"] != "evil.example"
    assert service.config["email"].get("password") != "from-cwd"

    outside = tmp_path / "notification_config.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="config directory"):
        EnhancedNotificationService(config_file=str(outside))


def test_smtp_rejects_decimal_and_hex_loopback_hosts():
    service = EnhancedNotificationService()
    with pytest.raises(ValueError, match="restricted"):
        service._validate_smtp_target("2130706433", 587)
    with pytest.raises(ValueError, match="restricted"):
        service._validate_smtp_target("0x7f000001", 587)


def test_webhook_rejects_decimal_loopback_host():
    service = EnhancedNotificationService()
    with pytest.raises(ValueError, match="private or restricted"):
        service._validate_webhook_url("https://2130706433/hook")


def test_backup_directory_cannot_leave_project_or_database(temp_db_path):
    with pytest.raises(ValueError, match="allowed directories"):
        EnhancedMusicDataStore(db_path=str(temp_db_path), backup_dir="/tmp/audora-backup-escape")


def test_spotify_token_cache_stays_inside_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache_path = spotify_token_cache_path()
    assert cache_path == project_root() / ".cache"
    assert cache_path.is_file()
    assert not (tmp_path / ".cache").exists()
    assert oct(cache_path.stat().st_mode & 0o777) == "0o600"
