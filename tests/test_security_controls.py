"""Tests for critical cache, SSRF, redirect, and CSV protections."""

import asyncio
import base64
import inspect
import json
import os
import sqlite3
from pathlib import Path

import aiohttp
import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.config import validate_spotify_redirect_uri
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    _PinnedConnector,
    _PinnedResolver,
)
from core.utils import (
    JsonTokenCache,
    _windows_short_aliases,
    dashboard_request_allowed,
    is_sensitive_filename,
    load_dataframe,
    neutralize_csv_frame,
    open_project_writer,
    read_json,
    read_nofollow_text,
    redact_secrets,
    resolve_project_path,
    save_dataframe,
    save_matplotlib_figure,
    save_plotly_html,
    write_json,
    write_private_text,
)
from integrations.api_config import SocialAPIManager
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
        encoded = backend._serialize("audora:track", {"track": "Song", "score": 3})
        assert json.loads(encoded)["v"] == 2
        assert backend._deserialize("audora:track", encoded) == {"track": "Song", "score": 3}

    def test_signature_is_bound_to_the_cache_key(self):
        backend = _redis_backend()
        encoded = backend._serialize("audora:tracks", {"track": "Song"})
        assert backend._deserialize("audora:tracks", encoded) == {"track": "Song"}
        assert backend._deserialize("audora:other", encoded) is None

    def test_rejects_legacy_pickle_envelope(self):
        backend = _redis_backend()
        payload = base64.b64encode(b"not-json-pickle").decode("ascii")
        envelope = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "abc", "payload": payload}
        ).encode()
        assert backend._deserialize("audora:legacy", envelope) is None

    def test_clear_does_not_flush_the_database(self):
        source = inspect.getsource(RedisCacheBackend.clear)
        assert "flushdb" not in source


class TestRedirectAndSsrf:
    def test_spotify_redirect_rejects_lookalike_hosts(self):
        validate_spotify_redirect_uri("http://127.0.0.1:8888/callback")
        validate_spotify_redirect_uri("http://localhost:8888/callback")
        validate_spotify_redirect_uri("http://127.0.0.1./callback")
        for uri in (
            "http://localhost.evil.com/callback",
            "http://127.0.0.1.evil.com/callback",
            "http://127.0.0.1@evil.com/callback",
            "http://@127.0.0.1/callback",
            "http://127.0.0.1../callback",
            "http://localhost../callback",
            "http://127.0.0.1:8888../callback",
            "http://127.0.0.1:08888/callback",
            "http://127.0.0.1:8888%40evil.com/callback",
            "http://127.0.0.1:8888/callback#",
            "http://127.1/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.1:8888/callback\r\nSet-Cookie",
            "http://127.0.0.1#@evil.com",
            "http://127.0.0.1:8888\\@evil.com/callback",
            "http://127.0.0.1:8888/callback\x7f",
            "http://127.0.0.1:8888/callback\u2028@evil.com",
            "http://127.0.0.1:8888/callback\u00a0@evil.com",
            "http://127.0.0.1:8888/callback\u0085",
            "http://localhost:8888/callback\ufeff",
            "http://127.0.0.1:8888/callback\u200b",
            "http://\u2028127.0.0.1:8888/callback",
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
            "https://example.com/\u2028hook",
            "https://example.com/\u200bhook",
            "https://example.com/\ufeffhook",
            "https://example.com/hook\u2028",
            "https://example.com/hook\u00a0",
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

    def test_webhook_rejects_client_host_mismatch(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="ambiguous"):
            svc._validate_webhook_url("https://ⓔxample.com/hook")

    def test_pinned_connector_screens_ip_literals(self):
        async def exercise() -> None:
            stock = aiohttp.TCPConnector()
            pinned = _PinnedConnector(resolver=_PinnedResolver("example.com", ["93.184.216.34"]))
            try:
                stock_result = await stock._resolve_host("127.0.0.1", 443)
                assert stock_result[0]["host"] == "127.0.0.1"
                with pytest.raises(OSError):
                    await pinned._resolve_host("127.0.0.1", 443)
                pinned_result = await pinned._resolve_host("example.com", 443)
                assert pinned_result[0]["host"] == "93.184.216.34"
            finally:
                await stock.close()
                await pinned.close()

        asyncio.run(exercise())

    def test_email_header_and_attachment_names_reject_controls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="control character"):
            svc._safe_header("Artist\r\nBcc: attacker@evil.com", "subject")
        with pytest.raises(ValueError, match="control character"):
            svc._safe_header("Artist\x0b", "subject")
        with pytest.raises(ValueError, match="unsafe characters"):
            svc._safe_attachment_name("report\r\nBcc: x.csv")
        assert svc._safe_attachment_name("trend.csv") == "trend.csv"
        assert svc._safe_header("Track\u200dTitle", "subject") == "Track\u200dTitle"
        with pytest.raises(ValueError, match="control character"):
            svc._safe_header("Artist\u2028Name", "subject")
        with pytest.raises(ValueError, match="Invalid SMTP host"):
            svc._validate_smtp_host("smtp.example.com\u2028", 587)

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

    def test_csv_sylk_prefix_is_neutralized(self):
        frame = pd.DataFrame({"ID": ["ID;P", " ID", "id_safe"]})
        neutralized = neutralize_csv_frame(frame)
        assert list(neutralized.columns) == ["'ID"]
        assert neutralized["'ID"].tolist() == ["'ID;P", "' ID", "id_safe"]

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

    def test_figure_writer_refuses_symlink_escape_and_credentials(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        outside = tmp_path.parent / "secret-figure.txt"
        outside.write_bytes(b"do-not-touch")
        link = tmp_path / "chart.png"
        link.symlink_to(outside)
        parent_link = tmp_path / "out"
        parent_link.symlink_to(tmp_path.parent)

        class _FakeFigure:
            def __init__(self) -> None:
                self.kwargs: dict[str, object] | None = None

            def savefig(self, handle, **kwargs) -> None:
                self.kwargs = kwargs
                handle.write(b"PNG")

            def to_html(self) -> str:
                return "<html>chart</html>"

        for target in (link, outside, parent_link / "secret-figure.txt", tmp_path / ".env"):
            with pytest.raises(ValueError), open_project_writer(target, binary=True) as handle:
                handle.write(b"overwritten")
        assert outside.read_bytes() == b"do-not-touch"

        figure = _FakeFigure()
        written = save_matplotlib_figure(figure, "data/chart.png", dpi=150)
        assert written.read_bytes() == b"PNG"
        assert figure.kwargs is not None
        assert figure.kwargs["format"] == "png"
        html_path = save_plotly_html(figure, "demo_visualizations/chart.html")
        assert html_path.read_text(encoding="utf-8") == "<html>chart</html>"
        assert outside.read_bytes() == b"do-not-touch"

    def test_refuses_hard_link_to_a_secret(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        outside = tmp_path.parent / "secret.env"
        outside.write_text("SPOTIFY_CLIENT_SECRET=leaked\n", encoding="utf-8")
        alias = tmp_path / "tracks.csv"
        os.link(outside, alias)

        for opener in (
            lambda: load_dataframe(alias),
            lambda: save_dataframe(pd.DataFrame({"a": ["x"]}), alias),
            lambda: write_json(alias, {"x": 1}),
            lambda: write_private_text(alias, "overwritten"),
            lambda: open_project_writer(alias, binary=True).__enter__(),
        ):
            with pytest.raises(ValueError, match="hard-linked"):
                opener()
        assert outside.read_text(encoding="utf-8") == "SPOTIFY_CLIENT_SECRET=leaked\n"

    def test_refuses_parent_directory_symlink(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("SECRET-ORIGINAL", encoding="utf-8")
        link = tmp_path / "link"
        link.symlink_to(outside, target_is_directory=True)

        with pytest.raises(ValueError, match="symlink"):
            read_nofollow_text(link / "secret.txt")
        with pytest.raises(ValueError, match="symlink"):
            write_private_text(link / "secret.txt", "OVERWRITTEN")
        with pytest.raises(ValueError, match="symlink"):
            write_private_text(link / "nested" / "new.txt", "OVERWRITTEN")

        assert secret.read_text(encoding="utf-8") == "SECRET-ORIGINAL"
        assert not (outside / "nested").exists()
        assert not (outside / "new.txt").exists()

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
            "id_rsa.",
            "id_rsa::$DATA",
            ".netrc",
            "credentials.json",
            "credentials",
            ".pgpass",
            "id_rsa.ppk",
            ".htpasswd",
            "config/notification_config.json.bak",
            "config/notification_config.json.",
            "config/notification_config.json.backup",
            ".id_rsa.swp",
            "id_ed25519_sk",
            ".envrc",
            "../secret.env",
            "ENV~1",
            "CREDEN~1.JSO",
            "NOTIFI~1.JSO",
            "ID_RSA~1",
            "TRENDS~1.SQL",
            "ENVPRO~1.LOC",
            ".env.production.local",
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

    def test_discovery_logging_rejects_symlinked_logs_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        source = Path("core/discovery_app.py").read_text(encoding="utf-8")
        assert 'logs_dir = resolve_project_path("logs")' in source
        outside = tmp_path.parent / "leaked-logs"
        outside.mkdir()
        (tmp_path / "logs").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            resolve_project_path("logs")
        assert list(outside.iterdir()) == []


class TestSecretRedactionAndDashboardHost:
    def test_redacts_api_keys_and_webhook_urls(self):
        leaked = (
            "GET /2.0/?method=chart.gettoptracks&api_key=abc123secret&format=json "
            "client_secret=spotify-secret "
            '{"client_secret": "json-secret", "password": "pw"} '
            "https://www.theaudiodb.com/api/v1/json/premium-key/search.php "
            "https://HOOKS.SLACK.COM/services/T00/B00/SECRETTOKEN "
            "https://ptb.discord.com/api/webhooks/123/discord-token "
            "Authorization: Bearer super-token"
        )
        redacted = redact_secrets(leaked)
        assert "abc123secret" not in redacted
        assert "spotify-secret" not in redacted
        assert "json-secret" not in redacted
        assert "premium-key" not in redacted
        assert "SECRETTOKEN" not in redacted
        assert "discord-token" not in redacted
        assert "super-token" not in redacted
        assert "REDACTED" in redacted

    def test_redacts_versioned_discord_and_custom_webhook_urls(self):
        leaked = (
            "https://discord.com/api/v10/webhooks/123/v10-token "
            "https://canary.discord.com/api/v9/webhooks/99/canary-token "
            "https://ptb.discordapp.com/api/v10/webhooks/77/ptb-token "
            "https://hooks.slack.com/workflows/T1/A1/111/workflow-token "
            "https://hooks.slack.com/triggers/T1/222/trigger-token "
            "https://hooks.slack-gov.com/services/T1/B1/gov-token "
            '{"webhook_url": "https://alerts.example.com/hook/json-token"} '
            "https://charts.spotify.com/chart"
        )
        redacted = redact_secrets(leaked)
        assert "v10-token" not in redacted
        assert "canary-token" not in redacted
        assert "ptb-token" not in redacted
        assert "workflow-token" not in redacted
        assert "trigger-token" not in redacted
        assert "gov-token" not in redacted
        assert "json-token" not in redacted
        assert "https://charts.spotify.com/chart" in redacted

        custom = "https://alerts.example.com/hooks/custom-secret-value"
        assert "custom-secret-value" not in redact_secrets(f"echo {custom}")
        plain = "https://alerts.example.com/ingest/plain-secret-value"
        assert plain in redact_secrets(f"echo {plain}")
        assert plain not in redact_secrets(f"echo {plain}", plain)
        # Shorter than 8 characters, so it must not be erased globally.
        assert redact_secrets("abcd abcd", "abcd") == "abcd abcd"

        service = EnhancedNotificationService.__new__(EnhancedNotificationService)
        service.config = {
            "webhook": {"url": plain},
            "slack": {"webhook_url": ""},
            "discord": {"webhook_url": ""},
            "email": {"password": "smtp-password-value"},
            "sms": {},
        }
        delivery_error = service._redact_delivery_error(
            NotificationChannel.WEBHOOK, f"ClientResponseError url={plain}"
        )
        assert "plain-secret-value" not in delivery_error
        mail_error = service._redact_delivery_error(
            NotificationChannel.EMAIL, "auth failed for smtp-password-value"
        )
        assert "smtp-password-value" not in mail_error

    def test_redacts_teams_office_and_http_slack_webhook_urls(self):
        teams = (
            "https://contoso.webhook.office.com/webhookb2/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@tenant/IncomingWebhook/"
            "teams-secret-value/22222222-2222-2222-2222-222222222222"
        )
        office = (
            "https://outlook.office.com/webhook/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@tenant/IncomingWebhook/"
            "office-secret-value/guid"
        )
        office365 = (
            "https://outlook.office365.com/webhook/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@tenant/IncomingWebhook/"
            "office365-secret-value/guid"
        )
        http_slack = "http://hooks.slack.com/services/T00/B00/http-slack-token"
        leaked = f"post {teams} {office} {office365} {http_slack}"
        redacted = redact_secrets(leaked)
        assert "teams-secret-value" not in redacted
        assert "office-secret-value" not in redacted
        assert "office365-secret-value" not in redacted
        assert "http-slack-token" not in redacted
        assert "https://charts.spotify.com/chart" in redact_secrets(
            "see https://charts.spotify.com/chart"
        )
        # Singular /webhook/ on an ordinary host is not a credential URL.
        ordinary = "https://example.com/webhook/docs"
        assert ordinary in redact_secrets(f"docs {ordinary}")

    def test_redacts_basic_and_discord_bot_authorization(self):
        secret = base64.b64encode(b"spotify-client-id:spotify-client-secret").decode("ascii")
        bot = "MTAxMjM0NTY3ODkwMTIz.AbCdEf.GhIjKlMnOpQrStUvWxYz012345"
        leaked = (
            "sending POST request to https://accounts.spotify.com/api/token "
            f"with Headers: {{'Authorization': 'Basic {secret}'}} "
            f"Authorization: Bot {bot} "
            "Bot started "
            "Basic authentication "
            "https://charts.spotify.com/chart "
            "https://example.com/webhook/docs"
        )
        redacted = redact_secrets(leaked)
        assert secret not in redacted
        assert bot not in redacted
        assert "Basic REDACTED" in redacted
        assert "Bot REDACTED" in redacted
        assert "Bot started" in redacted
        assert "Basic authentication" in redacted
        assert "https://charts.spotify.com/chart" in redacted
        assert "https://example.com/webhook/docs" in redacted

    def test_redacts_live_environment_secrets(self, monkeypatch):
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "spotify-live-secret")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
        monkeypatch.setenv("HOME", "/home/listener")
        redacted = redact_secrets("leaked spotify-live-secret in the body")
        assert "spotify-live-secret" not in redacted
        assert "http://127.0.0.1:8888/callback" in redact_secrets(
            "redirect http://127.0.0.1:8888/callback"
        )
        assert "/home/listener" in redact_secrets("wrote /home/listener/cache")

    def test_persisted_api_error_redacts_the_stored_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        (tmp_path / "config").mkdir()
        manager = SocialAPIManager("config/social_apis.json")
        secret = "raw-provider-key"
        manager.set_api_key("youtube", secret)
        manager.record_request("youtube", success=False, error=f"upstream echoed {secret}")
        stored = manager.get_config("youtube")
        assert stored is not None
        assert secret not in stored.last_error
        assert "REDACTED" in stored.last_error
        saved = (tmp_path / "config" / "social_apis.json").read_text(encoding="utf-8")
        assert saved.count(secret) == 1

    def test_disguised_secret_names_are_blocked(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        assert is_sensitive_filename("id_rsa.")
        assert is_sensitive_filename("id_rsa.bak")
        assert is_sensitive_filename("ID_RSA::$DATA")
        assert is_sensitive_filename(".netrc")
        assert is_sensitive_filename("notification_config.json ")
        assert is_sensitive_filename(".pgpass")
        assert is_sensitive_filename("credentials")
        assert is_sensitive_filename("credentials.bak")
        assert is_sensitive_filename("id_rsa.ppk")
        assert is_sensitive_filename(".htpasswd")
        assert is_sensitive_filename(".my.cnf")
        assert is_sensitive_filename(".boto")
        assert is_sensitive_filename(".s3cfg")
        assert is_sensitive_filename("vault.kdbx")
        assert is_sensitive_filename("key.p8")
        assert is_sensitive_filename("prod.tfstate")
        assert is_sensitive_filename(".id_rsa.swp")
        assert is_sensitive_filename(".credentials.json.swo")
        assert is_sensitive_filename("..env.swp")
        assert is_sensitive_filename("#id_rsa#")
        assert is_sensitive_filename("#id_rsa~#")
        assert is_sensitive_filename("#id_rsa.bak#")
        assert is_sensitive_filename("#id_rsa.swp#")
        assert is_sensitive_filename("#id_rsa.2#")
        assert is_sensitive_filename("#credentials.json.bak#")
        assert is_sensitive_filename("#.env~#")
        assert is_sensitive_filename("#.envrc~#")
        assert is_sensitive_filename("#.netrc~#")
        assert is_sensitive_filename("#.pgpass~#")
        assert is_sensitive_filename("#authorized_keys~#")
        assert is_sensitive_filename(".#id_ed25519")
        assert is_sensitive_filename("id_ed25519_sk")
        assert is_sensitive_filename("id_ecdsa_sk")
        assert is_sensitive_filename("id_rsa.2")
        assert is_sensitive_filename("credentials.json.backup")
        assert is_sensitive_filename("notification_config.json.backup")
        assert is_sensitive_filename(".envrc")
        assert is_sensitive_filename(".envrc.local")
        assert is_sensitive_filename("authorized_keys2")
        assert is_sensitive_filename("ENV~1")
        assert is_sensitive_filename("env~2")
        assert is_sensitive_filename("ENV~1.LOC")
        assert is_sensitive_filename("ENVRC~1")
        assert is_sensitive_filename("ID_RSA~1")
        assert is_sensitive_filename("ID_ED2~1")
        assert is_sensitive_filename("AUTHOR~1")
        assert is_sensitive_filename("CREDEN~1.JSO")
        assert is_sensitive_filename("CREDEN~1")
        assert is_sensitive_filename("NOTIFI~1.JSO")
        assert is_sensitive_filename("ENHANC~1.JSO")
        assert is_sensitive_filename("SOCIAL~1.JSO")
        assert is_sensitive_filename("ID_RSA~1.BAC")
        assert is_sensitive_filename("..env.swp")
        assert is_sensitive_filename("TRENDS~1.SQL")
        assert is_sensitive_filename("MUSIC~1.SQ~")
        assert is_sensitive_filename("VAULT~1.KDB")
        assert is_sensitive_filename("PROD~1.TFS")
        assert is_sensitive_filename("TRENDS~1.DB-")
        assert is_sensitive_filename("MY0DB9~1.CNF")
        assert is_sensitive_filename(".env.production.local")
        assert is_sensitive_filename(".env.development.local")
        assert is_sensitive_filename(".env.preview.local")
        assert is_sensitive_filename("ENVPRO~1.LOC")
        assert is_sensitive_filename("envpro~1.lo~")
        assert is_sensitive_filename("ENVDEV~1.LOC")
        assert is_sensitive_filename("ENVPRE~1.LOC")
        assert is_sensitive_filename("ENVPRO~1.LOC::$DATA")
        assert is_sensitive_filename(".env.production.local.bak")
        for long_name in (
            ".env.production.local",
            ".env.development.local",
            ".env.test.local",
            ".env.preview.local",
            ".env.production.local.bak",
        ):
            for alias in _windows_short_aliases(long_name):
                assert is_sensitive_filename(alias), alias
        for long_name in (
            ".env.canary.local",
            ".env.nightly.local",
            ".envrc.canary.local",
            ".env.canary.local.bak",
            ".env.canary.local.swp",
        ):
            aliases = _windows_short_aliases(long_name)
            checksum_aliases = [alias for alias in aliases if not alias.startswith("env")]
            assert checksum_aliases, long_name
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
                assert is_sensitive_filename(alias.upper() + "::$DATA"), alias
        assert is_sensitive_filename("ENVCAN~1.BAK")
        assert is_sensitive_filename("EN9DD6~1.LOC")
        assert is_sensitive_filename("EN9DD6~1.LO~")
        for long_name in (
            ".env.canary",
            ".env.nightly",
            ".envrc.canary",
            ".env.staging2",
            ".env.canary~",
            ".envrc.nightly",
        ):
            aliases = _windows_short_aliases(long_name)
            checksum_aliases = [alias for alias in aliases if not alias.startswith("env")]
            assert checksum_aliases, long_name
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
                assert is_sensitive_filename(alias.upper() + "::$DATA"), alias
        assert is_sensitive_filename("ENB38A~1.CAN")
        assert is_sensitive_filename("ENB38A~1.CA~")
        assert is_sensitive_filename("EN531C~1.NIG")
        assert is_sensitive_filename("EN43F9~1.CAN")
        for long_name in (".env.txt", ".env.csv", ".envrc.txt", ".envrc.csv", ".env.txt~"):
            aliases = _windows_short_aliases(long_name)
            checksum_aliases = [alias for alias in aliases if not alias.startswith("env")]
            assert checksum_aliases, long_name
            for alias in checksum_aliases:
                assert is_sensitive_filename(alias), alias
        assert is_sensitive_filename("EN8119~1.TXT")
        assert is_sensitive_filename("ENC86C~1.TX~")
        for long_name in (
            "#.env.canary#",
            "#.env.nightly#",
            "#.envrc.canary#",
            "#.env.canary.local#",
            "#.env.canary~#",
            ".#.env.canary",
            ".#.env.canary.local",
            "#.env.txt#",
            "#.env.csv#",
            "#.envrc.txt#",
            "#.envrc.csv#",
            "#.env.txt~#",
            ".#.env.txt",
            ".#.env.csv~",
        ):
            aliases = _windows_short_aliases(long_name)
            checksum_aliases = [alias for alias in aliases if alias.startswith("#e")]
            assert checksum_aliases, long_name
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
                assert is_sensitive_filename(alias.upper() + "::$DATA"), alias
        assert is_sensitive_filename("#EB57A~1.CAN")
        assert is_sensitive_filename("#EB57A~1.CA~")
        assert is_sensitive_filename("#E7E5E~1.LOC")
        assert is_sensitive_filename("#E7E5E~1.LO~")
        assert is_sensitive_filename("#E3F42~1.CAN")
        assert is_sensitive_filename("#E30C2~1.CAN")
        assert is_sensitive_filename("#EBCAB~1.TXT")
        assert is_sensitive_filename("#EBCAB~1.TX~")
        for long_name in (
            "#.env.canary.swp#",
            "#.env.nightly.swp#",
            "#.env.txt.swp#",
            "#.env.csv.swp#",
            "#.env.canary.local.swp#",
            "#.env.canary.swo#",
            "#.env.canary.swn#",
            "#.env.canary.swx#",
            ".#.env.canary.swp#",
            ".env.canary.swp~",
            ".env.nightly.swo~",
            ".env.txt.swp~",
        ):
            aliases = _windows_short_aliases(long_name)
            assert any(alias.endswith(".sw~") for alias in aliases), long_name
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
                assert is_sensitive_filename(alias.upper() + "::$DATA"), alias
        assert is_sensitive_filename("#ENVCA~1.SW~")
        assert is_sensitive_filename("#ENVNI~1.SW~")
        assert is_sensitive_filename("#ENVTX~1.SW~")
        assert is_sensitive_filename("ENVCAN~1.SW~")
        # ``#environment.txt.swp#`` collides with the truncated vim-swap
        # extension. ``#ENVIR~1.TXT`` (no swap) stays allowed below.
        assert is_sensitive_filename("#ENVIR~1.SW~")
        assert not is_sensitive_filename("ENTRY~1.SW~")
        assert not is_sensitive_filename("#ENTRY~1.SW~")
        for long_name in (
            "#secrets.pem#",
            "secrets.pem~",
            "#token.key#",
            "token.key~",
            "#client.p12#",
            "client.p12~",
            "#client.pfx#",
            "client.pfx~",
            "#login.ppk#",
            "login.ppk~",
        ):
            aliases = _windows_short_aliases(long_name)
            assert any(alias.endswith(("pe~", "ke~", "p1~", "pf~", "pp~")) for alias in aliases)
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
                assert is_sensitive_filename(alias.upper() + "::$DATA"), alias
        assert is_sensitive_filename("#SECRE~1.PE~")
        assert is_sensitive_filename("SECRET~1.PE~")
        assert is_sensitive_filename("#TOKEN~1.KE~")
        assert is_sensitive_filename("TOKEN~1.KE~")
        assert is_sensitive_filename("#CLIEN~1.P1~")
        assert is_sensitive_filename("CLIENT~1.P1~")
        assert is_sensitive_filename("#CLIEN~1.PF~")
        assert is_sensitive_filename("CLIENT~1.PF~")
        assert is_sensitive_filename("#LOGIN~1.PP~")
        assert is_sensitive_filename("LOGIN~1.PP~")
        # Safe-extension forms of ordinary documents that share those two
        # letters are refused on purpose. The untruncated extensions stay open.
        assert is_sensitive_filename("ARCHIV~1.PE~")
        assert not is_sensitive_filename("ARCHIV~1.PEO")
        assert is_sensitive_filename("README~1.KE~")
        assert is_sensitive_filename("SLIDES~1.PP~")
        assert not is_sensitive_filename("SLIDES~1.PPT")
        for plain_name in ("archive.people", "slides.pptx", "notes.txt", "report.csv"):
            assert not is_sensitive_filename(plain_name)
        for long_name in (
            "#.env~#",
            "#id_rsa.bak#",
            "#id_rsa.swp#",
            "#.netrc~#",
            "#credentials.json.bak#",
        ):
            aliases = _windows_short_aliases(long_name)
            assert aliases, long_name
            for alias in aliases:
                assert is_sensitive_filename(alias), alias
        assert not is_sensitive_filename("#id_safe~#")
        assert not is_sensitive_filename("#report.csv.bak#")
        assert not is_sensitive_filename("#notes.txt~#")
        for plain_name in ("#id_safe~#", "#report.csv.bak#", "#notes.txt~#"):
            for alias in _windows_short_aliases(plain_name):
                assert not is_sensitive_filename(alias), alias
        for plain_name in (
            "environment.txt",
            "environment.txt~",
            "envelope.csv",
            "envelope.csv~",
            "envprofile",
            "entry.txt",
            "entry.txt~",
            "energy.txt",
            "english.csv",
            "english.csv~",
            "envelope.txt",
            "#environment.txt#",
            "#environment.txt~#",
            "#envelope.csv#",
            "#entry.txt#",
            "#english.csv#",
            "#envprofile#",
            ".#environment.txt",
        ):
            for alias in _windows_short_aliases(plain_name):
                assert not is_sensitive_filename(alias), alias
        for alias in _windows_short_aliases("envelope.local"):
            assert is_sensitive_filename(alias), alias
        assert is_sensitive_filename("id_rsa.txt")
        assert is_sensitive_filename("id_rsa.lock")
        assert is_sensitive_filename("ID_RSA.TXT")
        assert is_sensitive_filename("id_rsa.txt.bak")
        assert is_sensitive_filename("#id_rsa.txt#")
        assert is_sensitive_filename("credentials.json.txt")
        assert is_sensitive_filename("credentials.json.dist")
        assert is_sensitive_filename("credentials.json.lock")
        assert is_sensitive_filename("notification_config.json.txt")
        assert is_sensitive_filename("client.pem.txt")
        assert is_sensitive_filename("server.key.lock")
        assert is_sensitive_filename("trends.db.txt")
        assert is_sensitive_filename("._.env")
        assert is_sensitive_filename("._.env.local")
        assert is_sensitive_filename("._id_rsa")
        assert is_sensitive_filename("._id_rsa.txt")
        assert is_sensitive_filename("._credentials.json")
        assert is_sensitive_filename("._.netrc")
        assert not is_sensitive_filename("id_rsa.pub")
        assert not is_sensitive_filename("ID_ED25519.PUB")
        assert not is_sensitive_filename("id_ecdsa_sk.pub")
        assert not is_sensitive_filename("._id_rsa.pub")
        assert not is_sensitive_filename("._report.csv")
        assert not is_sensitive_filename("my_credentials.csv")
        assert not is_sensitive_filename("MY_CRE~1.CSV")
        assert not is_sensitive_filename("report.csv")
        assert not is_sensitive_filename("CREDEN~1.CSV")
        assert not is_sensitive_filename("NOTES~1.TXT")
        assert not is_sensitive_filename("id_safe")
        assert not is_sensitive_filename("ID_SAF~1")
        assert not is_sensitive_filename("ENVIRO~1.TXT")
        assert not is_sensitive_filename("EN41DD~1.TXT")
        assert not is_sensitive_filename("ENVELO~1.CSV")
        assert not is_sensitive_filename("EN0EED~1.CSV")
        assert not is_sensitive_filename("ENVPRO~1")
        assert not is_sensitive_filename("ENA51B~1")
        assert not is_sensitive_filename("ENTRY~1.TXT")
        assert not is_sensitive_filename("ENC614~1.TXT")
        assert not is_sensitive_filename("EN29DD~1.TX~")
        assert not is_sensitive_filename("EN07DE~1.CS~")
        assert not is_sensitive_filename("#E829F~1.TXT")
        assert not is_sensitive_filename("#E829F~1.TX~")
        assert not is_sensitive_filename("#ENVIR~1.TXT")
        assert not is_sensitive_filename("#E3C38~1")
        assert not is_sensitive_filename("#ENVPR~1")
        assert not is_sensitive_filename("environment.txt")
        assert not is_sensitive_filename("envelope.csv")
        assert not is_sensitive_filename("envelope.local")
        (tmp_path / "config").mkdir()
        write_json("config/notification_config.json", {"email": {"password": "secret"}})
        assert read_json("config/notification_config.json")["email"]["password"] == "secret"
        with pytest.raises(ValueError, match="credential"):
            read_json("id_rsa.txt")
        with pytest.raises(ValueError, match="credential"):
            read_json("._.env")
        with pytest.raises(ValueError, match="credential"):
            read_json("credentials.json.txt")
        with pytest.raises(ValueError, match="credential"):
            read_json("config/notification_config.json.txt")
        with pytest.raises(ValueError, match="credential"):
            read_json("config/notification_config.json.bak")
        with pytest.raises(ValueError, match="credential"):
            read_json("config/notification_config.json.backup")
        with pytest.raises(ValueError, match="credential"):
            read_json(".id_rsa.swp")
        with pytest.raises(ValueError, match="credential"):
            read_json("NOTIFI~1.JSO")
        with pytest.raises(ValueError, match="credential"):
            read_json("ENV~1")
        with pytest.raises(ValueError, match="credential"):
            read_json("ENVPRO~1.LOC")
        with pytest.raises(ValueError, match="credential"):
            read_json("EN9DD6~1.LOC")
        with pytest.raises(ValueError, match="credential"):
            read_json("ENB38A~1.CAN")
        with pytest.raises(ValueError, match="credential"):
            read_json("ENB38A~1.CA~")
        with pytest.raises(ValueError, match="credential"):
            read_json("#EB57A~1.CAN")
        with pytest.raises(ValueError, match="credential"):
            read_json("#E7E5E~1.LOC")
        with pytest.raises(ValueError, match="credential"):
            read_json("#EBCAB~1.TXT")
        with pytest.raises(ValueError, match="credential"):
            read_json("#ENVCA~1.SW~")
        with pytest.raises(ValueError, match="credential"):
            read_json("ENVCAN~1.SW~")
        with pytest.raises(ValueError, match="credential"):
            read_json("#id_rsa.bak#")
        with pytest.raises(ValueError, match="credential"):
            read_json("#.env~#")
        with pytest.raises(ValueError, match="credential"):
            load_dataframe("EN9DD6~1.LO~")
        with pytest.raises(ValueError, match="credential"):
            load_dataframe("ENVDEV~1.LOC")
        with pytest.raises(ValueError, match="credential"):
            load_dataframe("TRENDS~1.SQL")
        with pytest.raises(ValueError, match="credential"):
            load_dataframe("config/notification_config.json")
        with pytest.raises(ValueError, match="credential"):
            save_dataframe(pd.DataFrame({"a": [1]}), "config/social_apis.json")

    def test_token_cache_does_not_follow_symlinks(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.utils.PROJECT_ROOT", tmp_path)
        cache = JsonTokenCache(tmp_path / ".cache")
        cache.save_token_to_cache({"access_token": "secret", "refresh_token": "r"})
        assert cache.get_cached_token() == {"access_token": "secret", "refresh_token": "r"}
        assert oct((tmp_path / ".cache").stat().st_mode)[-3:] == "600"
        outside = tmp_path.parent / "stolen-token"
        outside.write_text("original", encoding="utf-8")
        linked = tmp_path / ".cache"
        linked.unlink()
        linked.symlink_to(outside)
        with pytest.raises(ValueError):
            JsonTokenCache(linked).save_token_to_cache({"access_token": "secret"})
        assert outside.read_text(encoding="utf-8") == "original"

    def test_dashboard_rejects_rebind_and_cross_site_writes(self):
        assert dashboard_request_allowed("127.0.0.1:8050", None, None, "GET")
        assert dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:8050", "same-origin", "POST"
        )
        assert dashboard_request_allowed("[::1]:8050", None, "none", "GET")
        assert not dashboard_request_allowed("evil.example:8050", None, "same-origin", "POST")
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "https://evil.example", "cross-site", "POST"
        )
        assert not dashboard_request_allowed("127.0.0.1:8050", None, "cross-site", "POST")
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:9999", "same-site", "POST"
        )
        assert not dashboard_request_allowed(
            "localhost:8050", "http://127.0.0.1:8050", "same-origin", "POST"
        )
        assert not dashboard_request_allowed("127.0.0.1:8050", None, "same-origin", "POST")
        assert dashboard_request_allowed("127.0.0.1:8050", None, "cross-site", "GET")
        assert not dashboard_request_allowed("\u2028127.0.0.1:8050", None, None, "GET")
        assert not dashboard_request_allowed("127.0.0.1:8050\ufeff", None, None, "GET")
        assert dashboard_request_allowed(
            "127.0.0.1.:8050", "http://127.0.0.1.:8050", "same-origin", "POST"
        )
        assert not dashboard_request_allowed(
            "127.0.0.1..:8050", "http://127.0.0.1..:8050", "same-origin", "POST"
        )
        assert not dashboard_request_allowed("localhost..", None, None, "GET")
        assert not dashboard_request_allowed(
            "127.0.0.1:08050", "http://127.0.0.1:08050", "same-origin", "POST"
        )
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:08050", "same-origin", "POST"
        )
        assert not dashboard_request_allowed("[::1]:08050", None, None, "GET")
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:8050\r\n", "same-origin", "POST"
        )
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:8050\u00a0", "same-origin", "POST"
        )
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "http://127.0.0.1:8050\u3000", "same-origin", "POST"
        )
        assert not dashboard_request_allowed(
            "127.0.0.1:8050", "\u2028http://127.0.0.1:8050", "same-origin", "POST"
        )


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

    def test_reopen_does_not_follow_a_swapped_in_symlink(self, tmp_path, monkeypatch):
        from core.data_store import EnhancedMusicDataStore

        store = EnhancedMusicDataStore(
            str(tmp_path / "trends.db"), backup_dir=str(tmp_path / "backups")
        )
        store.close_pool()
        outside = tmp_path.parent / "secret.db"
        outside.write_text("SECRET-ORIGINAL", encoding="utf-8")
        db_path = Path(store.db_path)
        db_path.unlink()
        db_path.symlink_to(outside)
        monkeypatch.setattr(Path, "is_symlink", lambda _self: False)
        with pytest.raises(ValueError, match="symlink"), store.get_connection():
            pass
        assert outside.read_text(encoding="utf-8") == "SECRET-ORIGINAL"

    def test_open_refuses_hard_linked_database(self, tmp_path):
        from core.data_store import EnhancedMusicDataStore

        outside = tmp_path.parent / "secret-db-target.txt"
        outside.write_text("SECRET-ORIGINAL", encoding="utf-8")
        db_path = tmp_path / "trends.db"
        os.link(outside, db_path)
        with pytest.raises(ValueError, match="hard-linked"):
            EnhancedMusicDataStore(str(db_path), backup_dir=str(tmp_path / "backups"))
        assert outside.read_text(encoding="utf-8") == "SECRET-ORIGINAL"

    def test_wal_refuses_hard_linked_shared_memory_file(self, tmp_path):
        from core.data_store import EnhancedMusicDataStore

        secret = tmp_path.parent / "id_rsa"
        secret.write_text("PRIVATE-KEY-DATA\n", encoding="utf-8")
        db_path = tmp_path / "trends.db"
        os.link(secret, Path(f"{db_path}-shm"))
        with pytest.raises(ValueError, match="hard-linked"):
            EnhancedMusicDataStore(str(db_path), backup_dir=str(tmp_path / "backups"))
        assert secret.read_text(encoding="utf-8") == "PRIVATE-KEY-DATA\n"
        assert secret.stat().st_size == len("PRIVATE-KEY-DATA\n")

    def test_database_refuses_parent_directory_symlink(self, tmp_path):
        from core.data_store import EnhancedMusicDataStore

        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "trends.db"
        secret.write_text("SECRET-ORIGINAL", encoding="utf-8")
        link = tmp_path / "data"
        link.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            EnhancedMusicDataStore(str(link / "trends.db"), backup_dir=str(tmp_path / "backups"))
        assert secret.read_text(encoding="utf-8") == "SECRET-ORIGINAL"

    def test_log_handler_refuses_hard_link(self, tmp_path):
        from core.logging_config import NofollowFileHandler

        outside = tmp_path.parent / "secret-log.txt"
        outside.write_text("SECRET-ORIGINAL", encoding="utf-8")
        target = tmp_path / "app.log"
        os.link(outside, target)
        with pytest.raises(OSError, match="hard-linked"):
            NofollowFileHandler(target)
        assert outside.read_text(encoding="utf-8") == "SECRET-ORIGINAL"
