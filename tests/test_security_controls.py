"""Tests for critical cache, webhook, export, and CSV hardening."""

import json
from datetime import datetime

import pandas as pd
import pytest

from core.caching import dumps_signed, loads_signed
from core.config import _is_loopback_redirect_uri
from core.data_store import EnhancedMusicDataStore
from core.notification_service import (
    EnhancedNotificationService,
    _html_email_document,
    _open_smtp,
    _validate_smtp_target,
)
from core.utils import neutralize_dataframe_for_csv
from integrations.audiodb_integration import AudioDBAPI
from integrations.musicbrainz_integration import MusicBrainzAPI
from integrations.spotify_charts_integration import SpotifyChartsAPI


class TestSignedCache:
    """HMAC-signed JSON cache payloads reject pickle and tampering."""

    def test_round_trip_structured_values(self):
        key = b"test-signing-key"
        frame = pd.DataFrame({"name": ["=1+1"], "score": [1]})
        original = {
            "when": datetime(2026, 9, 22, 12, 0, 0),
            "pair": (1, "two"),
            "frame": frame,
            "items": [1, "ok", None],
        }
        restored = loads_signed(dumps_signed(original, key), key)
        assert restored["when"] == original["when"]
        assert restored["pair"] == original["pair"]
        assert restored["items"] == original["items"]
        assert restored["frame"]["name"].tolist() == ["=1+1"]

    def test_rejects_pickle_and_tampered_payloads(self):
        key = b"test-signing-key"
        signed = dumps_signed({"ok": True}, key)
        with pytest.raises(ValueError, match="pickle"):
            loads_signed(b"\x80\x04\x95\x00", key)
        envelope = json.loads(signed)
        envelope["sig"] = "0" * len(envelope["sig"])
        tampered = json.dumps(envelope).encode("utf-8")
        with pytest.raises(ValueError, match="signature"):
            loads_signed(tampered, key)
        with pytest.raises(ValueError, match="signature"):
            loads_signed(signed, b"other-key")


class TestWebhookValidation:
    """SSRF checks for outbound webhook targets."""

    def test_rejects_credentials_obfuscated_literals_and_metadata(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:secret@example.com/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://2130706433/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://0177.0.0.1/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::1]/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://metadata.google.internal/latest")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_html_email_escapes_untrusted_content(self):
        document = _html_email_document("<script>alert(1)</script>\nnext")
        assert "<script>" not in document
        assert "&lt;script&gt;" in document
        assert "<br>" in document


class TestCsvExportHardening:
    """Formula neutralization and export path confinement."""

    def test_neutralizes_object_and_string_columns(self):
        object_frame = pd.DataFrame({"formula": ["=1+1", "safe"], "n": [1, 2]})
        object_sanitized = neutralize_dataframe_for_csv(object_frame)
        assert object_sanitized["formula"].tolist() == ["'=1+1", "safe"]
        string_frame = object_frame.copy()
        string_frame["formula"] = string_frame["formula"].astype("string")
        sanitized = neutralize_dataframe_for_csv(string_frame)
        assert sanitized["formula"].tolist() == ["'=1+1", "safe"]
        assert sanitized["n"].tolist() == [1, 2]

    def test_export_stays_beside_database_and_neutralizes_cells(self, tmp_path):
        db_path = tmp_path / "music.db"
        store = EnhancedMusicDataStore(db_path=str(db_path), backup_dir=str(tmp_path / "backups"))
        try:
            with store.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO trends (
                        platform, track_id, track_name, artist, score, rank, region,
                        trend_date, first_detected, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "spotify",
                        "tid",
                        "=1+1",
                        "Artist",
                        10,
                        1,
                        "US",
                        "2026-09-22T00:00:00",
                        "2026-09-22T00:00:00",
                        "2026-09-22T00:00:00",
                    ),
                )
                conn.commit()
            exported = store.export_to_csv("trends", "../outside.csv")
            assert exported.endswith("/exports/outside.csv")
            contents = (tmp_path / "exports" / "outside.csv").read_text(encoding="utf-8")
            assert "'=1+1" in contents
            with pytest.raises(ValueError, match="csv"):
                store.export_to_csv("trends", "notes.txt")
        finally:
            store.close_pool()


class TestSmtpAndConfigHardening:
    """SMTP targets cannot point at loopback, and stored passwords are not reused."""

    def test_rejects_loopback_metadata_and_obfuscated_literals(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc.set_email_transport(smtp_server="localhost")
        with pytest.raises(ValueError, match="restricted"):
            svc.set_email_transport(smtp_server="127.0.0.1")
        with pytest.raises(ValueError, match="restricted"):
            svc.set_email_transport(smtp_server="2130706433")
        with pytest.raises(ValueError, match="restricted"):
            svc.set_email_transport(smtp_server="169.254.169.254")
        with pytest.raises(ValueError, match="metadata"):
            svc.set_email_transport(smtp_server="metadata.google.internal")
        svc.set_email_transport(smtp_server="10.0.0.1", password="kept")
        assert svc.config["email"]["smtp_server"] == "10.0.0.1"
        assert svc.config["email"]["password"] == "kept"

    def test_hostname_resolving_to_loopback_is_rejected(self, monkeypatch):
        monkeypatch.setattr(
            "core.notification_service.socket.getaddrinfo",
            lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))],
        )
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="restricted"):
            svc.set_email_transport(smtp_server="mail.example.com")

    def test_host_change_drops_password_and_config_is_private(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        svc = EnhancedNotificationService()
        svc.set_email_transport(smtp_server="10.1.2.3", password="secret-value")
        svc.set_email_transport(smtp_server="10.1.2.3", username="alice")
        assert svc.config["email"]["password"] == "secret-value"
        svc.set_email_transport(smtp_server="10.2.3.4")
        assert svc.config["email"]["password"] == ""
        svc.set_email_transport(smtp_server="10.2.3.4", password="next-secret")
        svc.save_config()
        saved = tmp_path / "config" / "notification_config.json"
        mode = saved.stat().st_mode & 0o777
        assert mode == 0o600
        assert "next-secret" in saved.read_text(encoding="utf-8")
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config("../notification_config.json")

    def test_smtp_dials_pinned_address_after_dns_changes(self, monkeypatch):
        answers = [[(2, 1, 6, "", ("203.0.113.10", 0))]]

        def fake_getaddrinfo(*_args, **_kwargs):
            if not answers:
                return [(2, 1, 6, "", ("127.0.0.1", 0))]
            return answers.pop(0)

        monkeypatch.setattr("core.notification_service.socket.getaddrinfo", fake_getaddrinfo)
        target = _validate_smtp_target("mail.example.com")
        assert target.addresses == ("203.0.113.10",)
        connected: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                self._host = ""

            def connect(self, host, port=0, source_address=None):
                connected["host"] = host
                connected["port"] = port
                return (220, b"ok")

            def ehlo(self):
                return (250, b"ok")

            def starttls(self, context=None):
                connected["sni"] = self._host
                return (220, b"tls")

            def close(self):
                connected["closed"] = True

        monkeypatch.setattr("core.notification_service.smtplib.SMTP", FakeSMTP)
        _open_smtp(target.hostname, 587, target.addresses)
        assert connected["host"] == "203.0.113.10"
        assert connected["port"] == 587
        assert connected["sni"] == "mail.example.com"
        assert "closed" not in connected


class TestRedirectAndOutboundRequests:
    """OAuth redirects and third-party clients must not leak credentials or follow redirects."""

    def test_spotify_redirect_requires_a_real_loopback_host(self):
        assert _is_loopback_redirect_uri("http://127.0.0.1:8888/callback")
        assert _is_loopback_redirect_uri("http://localhost:8888/callback")
        assert _is_loopback_redirect_uri("http://[::1]:8888/callback")
        assert not _is_loopback_redirect_uri("http://localhost.evil.example/callback")
        assert not _is_loopback_redirect_uri("http://127.0.0.1.evil.example/callback")
        assert not _is_loopback_redirect_uri("http://127.0.0.1@evil.example/callback")
        assert not _is_loopback_redirect_uri("http://localhost@evil.example/callback")
        assert not _is_loopback_redirect_uri("https://127.0.0.1/callback")
        assert not _is_loopback_redirect_uri("http://2130706433/callback")
        assert not _is_loopback_redirect_uri("http://8.8.8.8/callback")

    def test_audiodb_keeps_the_api_key_on_the_original_host(self):
        api = AudioDBAPI(api_key="premium-key")
        with pytest.raises(ValueError, match="endpoint"):
            api._make_request("../search.php")
        with pytest.raises(ValueError, match="API key"):
            AudioDBAPI(api_key="bad/key")._make_request("search.php")

        calls: dict[str, object] = {}

        class Response:
            is_redirect = False

            def raise_for_status(self):
                return None

            def json(self):
                return {"ok": True}

        def fake_get(url, params=None, timeout=None, allow_redirects=None):
            calls["url"] = url
            calls["allow_redirects"] = allow_redirects
            return Response()

        api.session.get = fake_get
        assert api._make_request("search.php", {"s": "a"}) == {"ok": True}
        assert calls["allow_redirects"] is False
        assert calls["url"] == "https://www.theaudiodb.com/api/v1/json/premium-key/search.php"
        assert api.session.trust_env is False

    def test_spotify_charts_reject_path_injection(self):
        api = SpotifyChartsAPI()
        called = {"count": 0}

        def fake_get(*_args, **_kwargs):
            called["count"] += 1
            raise AssertionError("chart request should not be sent")

        api.session.get = fake_get
        frame = api.get_top_200_daily(country_code="../@evil.example", date="2024-01-15")
        assert frame.empty
        assert called["count"] == 0
        assert api.session.trust_env is False

    def test_musicbrainz_rejects_path_rewriting(self):
        api = MusicBrainzAPI()
        called = {"count": 0}

        def fake_get(*_args, **_kwargs):
            called["count"] += 1
            raise AssertionError("MusicBrainz request should not be sent")

        api.session.get = fake_get
        assert api.get_artist_details("../../admin") is None
        assert api.get_artist_details("not-a-uuid") is None
        assert called["count"] == 0
        assert api.session.trust_env is False

        calls: dict[str, object] = {}

        class Response:
            is_redirect = False

            def raise_for_status(self):
                return None

            def json(self):
                return {"id": "5b11f4ce-a62d-471e-81fc-a69a8278c7da"}

        def safe_get(url, params=None, timeout=None, allow_redirects=None):
            calls["url"] = url
            calls["allow_redirects"] = allow_redirects
            calls["timeout"] = timeout
            return Response()

        api.session.get = safe_get
        result = api.get_artist_details("5b11f4ce-a62d-471e-81fc-a69a8278c7da")
        assert result is not None
        assert calls["allow_redirects"] is False
        assert calls["url"] == (
            "https://musicbrainz.org/ws/2/artist/5b11f4ce-a62d-471e-81fc-a69a8278c7da"
        )

    def test_platform_identifiers_cannot_escape_their_api(self):
        import asyncio
        import sys
        from pathlib import Path

        integrations = str(Path(__file__).resolve().parents[1] / "integrations")
        sys.path.insert(0, integrations)
        try:
            from extended_platforms import DiscordMusicBot, RedditMusicAPI, TumblrMusicAPI
        finally:
            if integrations in sys.path:
                sys.path.remove(integrations)

        calls: list[tuple[str, dict]] = []

        class _Response:
            status = 200

            async def json(self):
                return {"data": {"children": []}, "response": []}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            def get(self, url, **kwargs):
                calls.append((url, kwargs))
                return _Response()

            def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return _Response()

        import extended_platforms

        extended_platforms._http_session = lambda: _Session()

        reddit = RedditMusicAPI("id", "secret")
        reddit.access_token = "token"
        reddit.token_expires = datetime.max
        assert asyncio.run(reddit.get_music_subreddit_posts("../../api/v1/me")) == []
        assert calls == []

        tumblr = TumblrMusicAPI("key", "secret")
        assert asyncio.run(tumblr.get_music_blog_posts("../../oauth/request_token")) == []
        assert calls == []

        discord = DiscordMusicBot("bot-token")
        assert asyncio.run(discord.get_guild_voice_activity("../../users/@me")) == {}
        assert calls == []

        asyncio.run(reddit.get_music_subreddit_posts("popheads"))
        assert calls[0][0] == "https://oauth.reddit.com/r/popheads/hot"
        assert calls[0][1]["allow_redirects"] is False
        sys.modules.pop("extended_platforms", None)
        sys.modules.pop("social_discovery_engine", None)
