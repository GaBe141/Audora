"""Regression tests for outbound URL, export, and redirect hardening."""

import asyncio

import pytest

from core.config import SecureConfig
from core.utils import confine_to_project, neutralize_csv_value
from integrations.audiodb_integration import AudioDBAPI
from integrations.extended_platforms import DiscordMusicBot, RedditMusicAPI, TumblrMusicAPI
from integrations.lastfm_integration import BASE_URL
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import SpotifyChartsAPI


def test_lastfm_uses_https():
    assert BASE_URL == "https://ws.audioscrobbler.com/2.0/"


def test_redirect_uri_requires_exact_loopback_host(monkeypatch, tmp_path):
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://localhost.evil.com/callback")
    config = SecureConfig(env_file=tmp_path / "missing.env")
    with pytest.raises(ValueError, match="Invalid redirect URI"):
        config.get_spotify_config()

    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
    allowed = SecureConfig(env_file=tmp_path / "missing.env")
    assert allowed.get_spotify_config()["redirect_uri"] == "http://127.0.0.1:8888/callback"


def test_dotenv_does_not_override_existing_environment(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SPOTIFY_CLIENT_ID=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "from-env")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
    config = SecureConfig(env_file=env_file)
    assert config.get_spotify_config()["client_id"] == "from-env"


def test_csv_formula_neutralization_includes_leading_whitespace():
    assert neutralize_csv_value("=1+1") == "'=1+1"
    assert neutralize_csv_value(" =1+1") == "' =1+1"
    assert neutralize_csv_value("\t@cmd") == "'\t@cmd"
    assert neutralize_csv_value("Ada") == "Ada"


def test_export_path_cannot_leave_project():
    with pytest.raises(ValueError, match="project directory"):
        confine_to_project("/tmp/audora-escape.csv")


def test_musicbrainz_rejects_path_escape():
    api = MusicBrainzAPI()
    assert api.get_artist_details("../admin") is None
    assert api._make_request("artist/../../secret", {}) is None


def test_audiodb_rejects_path_escape():
    api = AudioDBAPI(api_key="123")
    assert api._make_request("../secret") is None


def test_spotify_charts_rejects_path_escape():
    api = SpotifyChartsAPI()
    assert api.get_top_200_daily(country_code="../evil", date="2020-01-01").empty
    assert api.get_viral_50_daily(country_code="us", date="2020-01-01/../../x").empty


def test_social_identifiers_are_allowlisted():
    reddit = RedditMusicAPI("client", "secret")
    tumblr = TumblrMusicAPI("key", "secret")
    discord = DiscordMusicBot("token")
    assert asyncio.run(reddit.get_music_subreddit_posts("../private")) == []
    assert asyncio.run(tumblr.get_music_blog_posts("../../other")) == []
    assert asyncio.run(discord.get_guild_voice_activity("not-a-snowflake")) == {}
