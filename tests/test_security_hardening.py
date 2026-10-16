"""Tests for critical cache, CSV, redirect, and outbound-request hardening."""

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from core.auth import spotify_token_cache_path
from core.caching import deserialize_cache_value, serialize_cache_value
from core.config import SecureConfig
from core.data_store import EnhancedMusicDataStore, database_path_from_config
from core.logging_config import setup_logging
from core.main_app import ComprehensiveMusicDiscoveryApp
from core.notification_service import EnhancedNotificationService
from core.utils import (
    confine_child_path,
    load_dataframe,
    neutralize_csv_frame,
    neutralize_csv_value,
    project_root,
    read_json,
)
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


def test_json_and_csv_reads_cannot_leave_project(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text('{"token":"super-secret"}', encoding="utf-8")
    assert read_json(secret, default={}) == {}

    csv_path = tmp_path / "secret.csv"
    csv_path.write_text("password\nsecret\n", encoding="utf-8")
    assert load_dataframe(csv_path, default_empty=True).empty


def test_child_path_rejects_traversal():
    with pytest.raises(ValueError, match="data directory"):
        confine_child_path("data", "../../.env")
    with pytest.raises(ValueError, match="data directory"):
        confine_child_path("data", "/etc/passwd")


def test_discovery_database_path_cannot_leave_project():
    with pytest.raises(ValueError, match="allowed directories"):
        database_path_from_config({"path": "/tmp/audora-escape.db"})
    configured = database_path_from_config({"database": {"path": "data/enhanced_music_trends.db"}})
    assert configured == project_root() / "data" / "enhanced_music_trends.db"


def test_relative_database_path_stays_in_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = EnhancedMusicDataStore(db_path="cwd-planted.db", backup_dir="backups")
    try:
        assert Path(store.db_path) == project_root() / "cwd-planted.db"
        assert not (tmp_path / "cwd-planted.db").exists()
        assert oct(Path(store.db_path).stat().st_mode & 0o777) == "0o600"
    finally:
        store.close_pool()
        Path(store.db_path).unlink(missing_ok=True)


def test_database_symlink_is_rejected(tmp_path):
    target = tmp_path / "real.db"
    target.touch()
    link = tmp_path / "link.db"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        EnhancedMusicDataStore(db_path=str(link), backup_dir=str(tmp_path / "backups"))


def test_report_directory_cannot_leave_project():
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="allowed directories"):
        app.save_discovery_report({}, custom_filename="/tmp/audora-report-escape.json")


@pytest.mark.parametrize(
    "url",
    [
        "https://0177.0.0.1/hook",
        "https://127.1/hook",
        "https://127.0.1/hook",
        "https://0x7f.0.0.1/hook",
    ],
)
def test_webhook_rejects_obfuscated_loopback(url):
    service = EnhancedNotificationService()
    with pytest.raises(ValueError, match="private or restricted"):
        service._validate_webhook_url(url)


def test_smtp_rejects_obfuscated_loopback():
    service = EnhancedNotificationService()
    with pytest.raises(ValueError, match="Localhost"):
        service._validate_smtp_target("127.1", 587)
    with pytest.raises(ValueError, match="Localhost"):
        service._validate_smtp_target("0177.0.0.1", 587)


def test_log_file_cannot_leave_project(tmp_path):
    with pytest.raises(ValueError, match="allowed directories"):
        setup_logging(log_dir=str(tmp_path), file_output=True, console_output=False)
    with pytest.raises(ValueError, match="app name"):
        setup_logging(app_name="../evil", file_output=True, console_output=False)


def test_spotify_token_cache_stays_inside_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache_path = spotify_token_cache_path()
    assert cache_path == project_root() / ".cache"
    assert cache_path.is_file()
    assert not (tmp_path / ".cache").exists()
    assert oct(cache_path.stat().st_mode & 0o777) == "0o600"
