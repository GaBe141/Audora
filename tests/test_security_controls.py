"""Tests for critical cache, SSRF, redirect, and CSV protections."""

import asyncio
import base64
import inspect
import json
import sqlite3
from pathlib import Path

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.config import validate_spotify_redirect_uri
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from core.utils import (
    dashboard_request_allowed,
    load_dataframe,
    neutralize_csv_frame,
    read_json,
    redact_secrets,
    resolve_project_path,
    save_dataframe,
    write_json,
)
from integrations.extended_platforms import safe_path_segment
from integrations.musicbrainz_integration import _require_mbid
from integrations.spotify_charts_integration import _safe_chart_target
from scripts.setup import EnhancedMusicDiscoverySetup


def _redis_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    backend._key_prefix = "audora:"
    return backend


class TestCacheEnvelope:
    def test_json_envelope_round_trip(self):
        backend = _redis_backend()
        encoded = backend._serialize({"track": "Song", "score": 3})
        assert json.loads(encoded)["v"] == 2
        assert backend._deserialize(encoded) == {"track": "Song", "score": 3}

    def test_rejects_legacy_pickle_envelope(self):
        backend = _redis_backend()
        payload = base64.b64encode(b"not-json-pickle").decode("ascii")
        envelope = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "abc", "payload": payload}
        ).encode()
        assert backend._deserialize(envelope) is None

    def test_clear_does_not_flush_the_database(self):
        source = inspect.getsource(RedisCacheBackend.clear)
        assert "flushdb" not in source


class TestRedirectAndSsrf:
    def test_spotify_redirect_rejects_lookalike_hosts(self):
        validate_spotify_redirect_uri("http://127.0.0.1:8888/callback")
        validate_spotify_redirect_uri("http://localhost:8888/callback")
        for uri in (
            "http://localhost.evil.com/callback",
            "http://127.0.0.1.evil.com/callback",
            "http://127.0.0.1@evil.com/callback",
            "http://127.1/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.1:8888/callback\r\nSet-Cookie",
            "http://127.0.0.1#@evil.com",
            "http://127.0.0.1:8888\\@evil.com/callback",
            "http://127.0.0.1:8888/callback\x7f",
        ):
            with pytest.raises(ValueError):
                validate_spotify_redirect_uri(uri)

    def test_blocks_metadata_and_obfuscated_webhook_hosts(self):
        svc = EnhancedNotificationService()
        blocked = (
            "https://127.0.0.1/hook",
            "https://100.100.100.200/hook",
            "https://2130706433/hook",
            "https://127.1/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
            "https://[fd00:ec2::254]/hook",
            "https://[2001::1]/hook",
            "https://[64:ff9b::8.8.8.8]/hook",
            "https://192.88.99.1/hook",
            "https://[fec0::1]/hook",
            "https://168.63.129.16/hook",
            "https://[::10.0.0.1]/hook",
            "https://[::127.0.0.1]/hook",
            "https://[::169.254.169.254]/hook",
            "https://[::ffff:0:10.0.0.1]/hook",
            "https://[fd00::1]/hook",
            "https://example.com\\@127.0.0.1/hook",
            "https://evil.com\r\n.127.0.0.1/hook",
            "https://①②⑦.0.0.1/hook",
        )
        for url in blocked:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_allows_public_ipv4_mapped_literal(self):
        svc = EnhancedNotificationService()
        url = "https://[::ffff:8.8.8.8]/hook"
        assert svc._validate_webhook_url(url) == url

    def test_private_webhook_opt_in_still_allows_rfc1918(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=False)

    def test_email_header_and_attachment_names_reject_controls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="control character"):
            svc._safe_header("Artist\r\nBcc: attacker@evil.com", "subject")
        with pytest.raises(ValueError, match="control character"):
            svc._safe_header("Artist\x0b", "subject")
        with pytest.raises(ValueError, match="unsafe characters"):
            svc._safe_attachment_name("report\r\nBcc: x.csv")
        assert svc._safe_attachment_name("trend.csv") == "trend.csv"

    def test_smtp_ssl_verifies_certificates(self):
        source = inspect.getsource(EnhancedNotificationService._send_email)
        assert "SMTP_SSL(context=ssl.create_default_context(), timeout=30)" in source
        host_at = source.index("server._host = hostname")
        connect_at = source.index("server.connect(pinned_ip, port)")
        assert host_at < connect_at

    def test_smtp_blocks_private_and_teredo_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("10.0.0.1", 587)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("2001::1", 587)
        with pytest.raises(ValueError, match="Invalid SMTP host"):
            svc._validate_smtp_host("smtp.example.com\x00.127.0.0.1", 587)


class TestPathAndCsvGuards:
    def test_csv_formula_neutralization(self):
        frame = pd.DataFrame(
            {
                "formula": [
                    "=1+1",
                    " =1+1",
                    "\t@cmd",
                    "\n=1+1",
                    "\u00a0+1",
                    "\x00-1",
                    "\ufeff@SUM(A1)",
                    "safe",
                ],
                "score": [1, 2, 3, 4, 5, 6, 7, 8],
            }
        )
        neutralized = neutralize_csv_frame(frame)
        assert neutralized["formula"].tolist() == [
            "'=1+1",
            "' =1+1",
            "'\t@cmd",
            "'\n=1+1",
            "'\u00a0+1",
            "'\x00-1",
            "'\ufeff@SUM(A1)",
            "safe",
        ]
        assert neutralized["score"].tolist() == [1, 2, 3, 4, 5, 6, 7, 8]

    def test_csv_formula_headers_are_neutralized(self):
        frame = pd.DataFrame({"=cmd": [1], "safe": ["=1+1"]})
        neutralized = neutralize_csv_frame(frame)
        assert list(neutralized.columns) == ["'=cmd", "safe"]
        assert neutralized["safe"].tolist() == ["'=1+1"]

    def test_path_segment_and_chart_guards(self):
        assert safe_path_segment("popheads") == "popheads"
        with pytest.raises(ValueError):
            safe_path_segment("../etc")
        with pytest.raises(ValueError):
            _require_mbid("not-a-uuid")
        assert _safe_chart_target("US", "2026-10-16") == ("us", "2026-10-16")
        with pytest.raises(ValueError):
            _safe_chart_target("global/../admin", "2026-10-16")
        with pytest.raises(ValueError):
            _safe_chart_target("global", "2026-13-40")


class TestProjectPathConfinement:
    def test_rejects_escape_credential_and_symlink(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        outside = tmp_path.parent / "secret.env"
        outside.write_text("SPOTIFY_CLIENT_SECRET=leaked\n", encoding="utf-8")
        inside = tmp_path / "tracks.csv"
        inside.write_text("name,score\nSong,1\n", encoding="utf-8")
        link = tmp_path / "linked.csv"
        link.symlink_to(outside)
        (tmp_path / ".env").write_text("SPOTIFY_CLIENT_SECRET=local\n", encoding="utf-8")

        frame = load_dataframe(inside)
        assert frame["name"].tolist() == ["Song"]
        write_json(tmp_path / "report.json", {"ok": True})
        assert read_json("report.json") == {"ok": True}

        for bad in ("../secret.env", outside, link):
            with pytest.raises(ValueError):
                resolve_project_path(bad)
            with pytest.raises(ValueError):
                load_dataframe(bad)
            with pytest.raises(ValueError):
                read_json(bad)
            with pytest.raises(ValueError):
                write_json(bad, {"x": 1})
            with pytest.raises(ValueError):
                save_dataframe(pd.DataFrame({"a": [1]}), bad)

        # Names inside the root still resolve, but generic IO must not touch them.
        for credential in (".env", ".env.local", ".ENV", ".ENV.enhanced", tmp_path / ".cache"):
            resolved = resolve_project_path(credential)
            assert resolved.parent == tmp_path
            with pytest.raises(ValueError, match="credential"):
                load_dataframe(credential)
            with pytest.raises(ValueError, match="credential"):
                read_json(credential)
            with pytest.raises(ValueError, match="credential"):
                write_json(credential, {"x": 1})
            with pytest.raises(ValueError, match="credential"):
                save_dataframe(pd.DataFrame({"a": [1]}), credential)

    def test_email_refuses_secret_and_database_attachments(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        (tmp_path / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
        (tmp_path / "trends.db").write_bytes(b"sqlite")
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["listener@example.com"]
        svc.config["email"]["from_address"] = "audora@example.com"

        for attachment in (
            ".env",
            "trends.db",
            "trends.db-wal",
            "config/social_apis.json",
            "id_rsa",
            "id_rsa.bak",
            "config/notification_config.json.bak",
            "../secret.env",
        ):
            message = NotificationMessage(
                title="Report",
                content="body",
                priority=NotificationPriority.LOW,
                channels=[NotificationChannel.EMAIL],
                attachments=[attachment],
            )
            result = asyncio.run(svc._send_email(message))
            assert result["success"] is False
            assert "secret" in result["error"].lower() or "escapes" in result["error"].lower()

    def test_setup_write_rejects_symlinked_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        outside = tmp_path.parent / "leaked-config"
        outside.mkdir()
        linked = tmp_path / "linked-config"
        linked.symlink_to(outside, target_is_directory=True)
        source = inspect.getsource(EnhancedMusicDiscoverySetup._setup_logging)
        assert "NofollowFileHandler" in source
        assert 'FileHandler("setup.log"' not in source
        setup = EnhancedMusicDiscoverySetup.__new__(EnhancedMusicDiscoverySetup)
        with pytest.raises(ValueError, match="escapes"):
            setup._write_private_file(linked / "social_apis.json", '{"api_key":"secret"}')
        assert not (outside / "social_apis.json").exists()


class TestSecretRedactionAndDashboardHost:
    def test_redacts_api_keys_and_webhook_urls(self):
        leaked = (
            "GET /2.0/?method=chart.gettoptracks&api_key=abc123secret&format=json "
            "https://www.theaudiodb.com/api/v1/json/premium-key/search.php "
            "https://hooks.slack.com/services/T00/B00/SECRETTOKEN "
            "Authorization: Bearer super-token"
        )
        redacted = redact_secrets(leaked)
        assert "abc123secret" not in redacted
        assert "premium-key" not in redacted
        assert "SECRETTOKEN" not in redacted
        assert "super-token" not in redacted
        assert "REDACTED" in redacted

    def test_dashboard_rejects_rebind_and_cross_site_writes(self):
        assert dashboard_request_allowed("127.0.0.1:8050", None, None, "GET")
        assert dashboard_request_allowed(
            "localhost:8050", "http://127.0.0.1:8050", "same-origin", "POST"
        )
        assert dashboard_request_allowed("[::1]:8050", None, "none", "GET")
        assert not dashboard_request_allowed("evil.example:8050", None, "same-origin", "POST")
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "https://evil.example", "cross-site", "POST"
        )
        assert not dashboard_request_allowed("127.0.0.1:8050", None, "cross-site", "POST")
        assert dashboard_request_allowed("127.0.0.1:8050", None, "cross-site", "GET")


class TestDatabaseBackup:
    def test_backup_stays_on_the_created_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.data_store.PROJECT_ROOT", tmp_path)
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        from core.data_store import EnhancedMusicDataStore

        store = EnhancedMusicDataStore(
            str(tmp_path / "trends.db"), backup_dir=str(tmp_path / "backups")
        )
        backup = store.create_backup()
        store.close_pool()
        backup_path = Path(backup)
        assert backup_path.is_file()
        assert not backup_path.is_symlink()

        with sqlite3.connect(backup) as conn:
            names = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert "trends" in names
