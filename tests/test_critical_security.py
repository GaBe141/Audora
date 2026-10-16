"""Tests for critical cache, webhook, export, and credential protections."""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import pickle
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import aiohttp
import pandas as pd
import pytest

if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from core.caching import deserialize_signed_json, serialize_signed_json
from core.config import SecureConfig
from core.data_store import EnhancedMusicDataStore
from core.notification_service import EnhancedNotificationService
from core.utils import neutralize_csv_value
from integrations.audiodb_integration import AudioDBAPI
from integrations.extended_platforms import DiscordMusicBot, RedditMusicAPI
from integrations.lastfm_integration import BASE_URL, LastFmAPI
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.safe_http import NoRedirectRequests, NoRedirectSession
from integrations.spotify_charts_integration import SpotifyChartsAPI


class TestSignedJsonCache:
    """Redis cache payloads must be signed JSON and must never be unpickled."""

    def test_round_trip_and_dataframe(self):
        key = b"cache-test-key"
        payload = {"artist": "A", "score": 1}
        encoded = serialize_signed_json(payload, key)
        assert deserialize_signed_json(encoded, key) == payload

        frame = pd.DataFrame([{"track": "Song", "score": 3}])
        restored = deserialize_signed_json(serialize_signed_json(frame, key), key)
        assert list(restored["track"]) == ["Song"]

    def test_rejects_wrong_key_and_pickle_envelopes(self):
        key = b"cache-test-key"
        encoded = serialize_signed_json({"ok": True}, key)
        assert deserialize_signed_json(encoded, b"other-key") is None

        pickled = pickle.dumps({"pwned": True})
        signature = hmac.new(key, pickled, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_signed_json(envelope, key) is None
        assert b"pickle" not in encoded


class TestWebhookAndSmtpGuards:
    """Webhook and SMTP targets cannot be steered onto loopback or link-local hosts."""

    def test_blocks_loopback_and_mapped_addresses_when_private_is_allowed(self):
        service = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            service._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            service._validate_webhook_url("https://[::ffff:10.0.0.1]/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            service._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_allows_explicit_private_ipv4_and_rejects_userinfo_or_port(self):
        service = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert service._validate_webhook_url(url, allow_private=True) == url
        with pytest.raises(ValueError, match="userinfo"):
            service._validate_webhook_url("https://user:pass@10.0.0.1/webhook", allow_private=True)
        with pytest.raises(ValueError, match="443"):
            service._validate_webhook_url("https://10.0.0.1:8443/webhook", allow_private=True)

    def test_smtp_rejects_localhost_and_unapproved_ports(self):
        service = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            service._resolve_smtp_target("localhost", 587)
        with pytest.raises(ValueError, match="Localhost"):
            service._resolve_smtp_target("127.0.0.1", 465)
        with pytest.raises(ValueError, match="465 or 587"):
            service._resolve_smtp_target("10.0.0.5", 25)

    def test_saved_config_omits_secrets_and_stays_under_config(self, tmp_path):
        service = EnhancedNotificationService()
        service.config["email"]["password"] = "super-secret"
        service.config["sms"]["api_key"] = "sms-key"
        service.config["webhook"]["headers"]["Authorization"] = "Bearer secret"
        destination = tmp_path / "notification_config.json"
        with pytest.raises(ValueError, match="config directory"):
            service.save_config(str(destination))

        project_config = (
            Path(__file__).resolve().parent.parent
            / "config"
            / "notification_config_security_test.json"
        )
        try:
            service.save_config(str(project_config))
            stored = json.loads(project_config.read_text(encoding="utf-8"))
            assert "password" not in stored["email"]
            assert "api_key" not in stored["sms"]
            assert "Authorization" not in stored["webhook"]["headers"]
            assert oct(project_config.stat().st_mode & 0o777) == "0o600"
        finally:
            project_config.unlink(missing_ok=True)


class TestCredentialAndExportGuards:
    """Credential files, OAuth redirects, and CSV exports stay in bounds."""

    def test_env_file_cannot_override_process_environment(self, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SPOTIFY_CLIENT_ID=from-file\n", encoding="utf-8")
        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "from-env")
        SecureConfig(env_file=str(env_file))
        assert os.environ["SPOTIFY_CLIENT_ID"] == "from-env"

    def test_redirect_uri_requires_exact_loopback_host(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "client")
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "secret")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://localhost.evil.com/callback")
        config = SecureConfig(env_file=tmp_path / "missing.env")
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            config.get_spotify_config()

        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8080/callback")
        assert config.get_spotify_config()["redirect_uri"].startswith("http://127.0.0.1")

    def test_csv_formula_and_export_path(self, tmp_path):
        assert neutralize_csv_value("=1+1").startswith("'")
        assert neutralize_csv_value(" =1+1").startswith("'")
        assert neutralize_csv_value("\t@cmd").startswith("'")
        assert neutralize_csv_value("normal") == "normal"

        store = EnhancedMusicDataStore(
            db_path=str(tmp_path / "trends.db"), backup_dir=str(tmp_path / "backups")
        )
        with pytest.raises(ValueError, match="allowed directory"):
            store.export_to_csv("trends", "/etc/passwd")
        exported = store.export_to_csv("trends", str(tmp_path / "trends.csv"))
        assert exported.endswith("trends.csv")
        store.close_pool()

    def test_lastfm_uses_https_without_redirects(self):
        assert BASE_URL.startswith("https://")
        api = LastFmAPI(api_key="abc")
        assert isinstance(api.session, NoRedirectRequests)
        assert api.session.trust_env is False

    def test_path_escapes_are_rejected_before_requests(self):
        assert AudioDBAPI(api_key="../../evil")._make_request("search.php") is None
        assert MusicBrainzAPI()._make_request("../admin", {}) is None
        assert SpotifyChartsAPI().get_top_200_daily(country_code="../etc", date="2020-01-01").empty

    def test_bearer_routes_reject_path_identifiers(self):
        reddit = RedditMusicAPI("id", "secret")
        reddit.access_token = "token"
        reddit.token_expires = datetime.now() + timedelta(hours=1)
        assert asyncio.run(reddit.get_music_subreddit_posts("../me")) == []
        discord_result = asyncio.run(DiscordMusicBot("token").get_guild_voice_activity("../@me"))
        assert discord_result == {}

    def test_aiohttp_wrapper_is_not_a_client_session(self):
        assert aiohttp.ClientSession not in NoRedirectSession.__mro__
