"""Tests for critical cache, webhook, export, and outbound URL controls."""

import asyncio
import json
import socket
import sys
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from core.caching import deserialize_cache_value, serialize_cache_value
from core.config import validate_spotify_redirect_uri
from core.notification_service import EnhancedNotificationService
from core.utils import confine_to_project, neutralize_csv_dataframe
from integrations.lastfm_integration import BASE_URL as LASTFM_BASE_URL
from integrations.lastfm_integration import LastFmAPI
from integrations.musicbrainz_integration import MusicBrainzAPI, safe_musicbrainz_endpoint
from integrations.spotify_charts_integration import SpotifyChartsAPI


class TestCacheSerialization:
    """Redis cache entries must be signed JSON, not pickle."""

    def test_round_trip_and_rejects_tampering(self):
        key = b"test-signing-key-32b-minimum!!"
        raw = serialize_cache_value({"artist": "Ada", "score": 3}, key)
        assert b"pickle" not in raw.lower()
        assert deserialize_cache_value(raw, key) == {"artist": "Ada", "score": 3}

        tampered = bytearray(raw)
        tampered[-2] = tampered[-2] ^ 1
        assert deserialize_cache_value(bytes(tampered), key) is None

    def test_rejects_legacy_pickle_envelope(self):
        legacy = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "ab", "payload": "gASVBQAAAAAAAACMBXBvc2l4lC4="}
        ).encode()
        assert deserialize_cache_value(legacy, b"test-signing-key-32b-minimum!!") is None


class TestRedirectAndWebhooks:
    """Redirect URIs and webhook targets must not point at unexpected hosts."""

    def test_spotify_redirect_requires_exact_loopback_host(self):
        assert validate_spotify_redirect_uri("http://127.0.0.1:8888/callback")
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            validate_spotify_redirect_uri("http://localhost.evil.example/callback")
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            validate_spotify_redirect_uri("http://user:pass@127.0.0.1:8888/callback")

    def test_webhook_blocks_loopback_metadata_and_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest/meta-data")
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="port 443"):
            svc._validate_webhook_url("https://example.com:8443/hook")

    def test_smtp_rejects_localhost_without_connecting(self):
        svc = EnhancedNotificationService()
        with patch("core.notification_service.socket.create_connection") as connect:
            with pytest.raises(ValueError, match="Localhost"):
                svc._validate_smtp_target("localhost", 587)
            with pytest.raises(ValueError, match="Localhost"):
                svc._validate_smtp_target("127.0.0.1", 587)
            connect.assert_not_called()

    def test_config_path_and_secret_redaction(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"]["password"] = "super-secret"
        svc.config["sms"]["api_key"] = "sms-secret"
        with pytest.raises(ValueError, match="outside the config directory"):
            svc._confine_config_path("../.env")

        config_dir = tmp_path / "config"
        config_dir.mkdir()
        monkeypatch.setattr("core.notification_service._PROJECT_ROOT", tmp_path)
        svc.save_config("config/notification_config.json")
        saved_path = config_dir / "notification_config.json"
        saved = json.loads(saved_path.read_text())
        assert "password" not in saved.get("email", {})
        assert "api_key" not in saved.get("sms", {})
        assert "super-secret" not in saved_path.read_text()


class TestExportsAndHistory:
    """CSV exports neutralize formulas and stay inside the project."""

    def test_formula_prefix_is_neutralized(self):
        frame = pd.DataFrame([{"artist": "=1+1", "title": "ok"}])
        neutralized = neutralize_csv_dataframe(frame)
        assert neutralized.loc[0, "artist"] == "'=1+1"
        assert neutralized.loc[0, "title"] == "ok"

    def test_export_path_cannot_escape_project(self):
        with pytest.raises(ValueError, match="escapes"):
            confine_to_project("../outside.csv")

    def test_artist_filter_is_literal(self):
        from gui.app import _filter_artists

        frame = pd.DataFrame([{"artist": "(a+)+$"}, {"artist": "Ada"}])
        matched = _filter_artists(frame, "(a+)+$")
        assert matched["artist"].tolist() == ["(a+)+$"]


class TestOutboundClients:
    """Upstream clients must not follow redirects or rewrite their API paths."""

    def test_lastfm_uses_https_without_redirects(self):
        api = LastFmAPI(api_key="test_key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"artists": {"artist": []}}
        with patch.object(api.session, "get", return_value=mock_response) as get:
            api._make_request("chart.gettopartists", limit=1)
        assert LASTFM_BASE_URL.startswith("https://")
        assert get.call_args.args[0] == LASTFM_BASE_URL
        assert get.call_args.kwargs["allow_redirects"] is False
        assert api.session.trust_env is False

    def test_musicbrainz_rejects_path_escape(self):
        with pytest.raises(ValueError, match="Invalid MusicBrainz"):
            safe_musicbrainz_endpoint("../ws/1/artist")
        api = MusicBrainzAPI()
        with patch.object(api.session, "get") as get:
            assert api.get_artist_details("../secret") is None
            get.assert_not_called()

    def test_charts_reject_path_segments(self):
        api = SpotifyChartsAPI()
        with patch.object(api.session, "get") as get:
            frame = api.get_top_200_daily(country_code="../admin", date="2024-01-15")
        assert frame.empty
        get.assert_not_called()

    def test_reddit_and_discord_reject_path_identifiers(self):
        from datetime import datetime

        from integrations.extended_platforms import DiscordMusicBot, RedditMusicAPI

        reddit = RedditMusicAPI("id", "secret")
        reddit.access_token = "token"
        reddit.token_expires = datetime.now() + timedelta(hours=1)
        with patch("integrations.extended_platforms._open_session") as session:
            posts = asyncio.run(reddit.get_music_subreddit_posts("../private"))
            assert posts == []
            session.assert_not_called()

        discord = DiscordMusicBot("bot-token")
        with patch("integrations.extended_platforms._open_session") as session:
            activity = asyncio.run(discord.get_guild_voice_activity("../channels"))
            assert activity == {}
            session.assert_not_called()

    def test_pinned_resolver_refuses_other_hosts(self):
        from core.notification_service import _PinnedResolver

        resolver = _PinnedResolver("hooks.example", ["93.184.216.34"])
        with pytest.raises(OSError, match="unexpected"):
            asyncio.run(resolver.resolve("169.254.169.254", 443, socket.AF_INET))
        pinned = asyncio.run(resolver.resolve("hooks.example", 443, socket.AF_INET))
        assert pinned[0]["host"] == "93.184.216.34"
