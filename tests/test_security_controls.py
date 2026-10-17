"""Tests for critical cache, SSRF, redirect, and CSV protections."""

import asyncio
import base64
import inspect
import json
import ssl

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
from core.utils import neutralize_csv_frame
from integrations.extended_platforms import safe_path_segment
from integrations.musicbrainz_integration import _require_mbid
from integrations.spotify_charts_integration import _safe_chart_target


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
            "https://[::ffff:169.254.169.254]/hook",
            "https://[::ffff:127.0.0.1]/hook",
        )
        for url in blocked:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_private_webhook_opt_in_still_allows_rfc1918(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        mapped = "https://[::ffff:10.0.0.1]/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url
        assert svc._validate_webhook_url(mapped, allow_private=True) == mapped
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=False)

    def test_smtp_blocks_private_and_teredo_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("10.0.0.1", 587)
        with pytest.raises(ValueError, match="SMTP server"):
            svc._validate_smtp_host("2001::1", 587)

    def test_implicit_smtp_tls_verifies_certificates(self, monkeypatch):
        captured: dict[str, object] = {}

        class FakeSMTPSSL:
            def __init__(self, timeout: float | None = None, context: ssl.SSLContext | None = None):
                captured["timeout"] = timeout
                captured["context"] = context
                self._host = ""

            def connect(self, host: str, port: int) -> tuple[int, bytes]:
                captured["host"] = host
                captured["port"] = port
                captured["tls_hostname"] = self._host
                return (220, b"ok")

            def login(self, user: str, password: str) -> None:
                return None

            def send_message(self, message: object) -> None:
                return None

            def quit(self) -> None:
                return None

        monkeypatch.setattr("core.notification_service.smtplib.SMTP_SSL", FakeSMTPSSL)
        monkeypatch.setattr(
            EnhancedNotificationService,
            "_validate_smtp_host",
            lambda self, host, port: ("smtp.example.com", "203.0.113.10"),
        )
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 465,
            "username": "user",
            "password": "secret",
            "from_address": "from@example.com",
            "recipients": ["to@example.com"],
            "use_tls": True,
        }
        message = NotificationMessage(
            title="hello",
            content="body",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        context = captured["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert captured["host"] == "203.0.113.10"
        assert captured["tls_hostname"] == "smtp.example.com"

    def test_attachment_filename_rejects_header_injection(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError):
            svc._safe_attachment_name("report.csv\r\nBcc: attacker@example.com")
        assert svc._safe_attachment_name("report.csv") == "report.csv"


class TestPathAndCsvGuards:
    def test_csv_formula_neutralization(self):
        frame = pd.DataFrame(
            {"formula": ["=1+1", " =1+1", "\t@cmd", "safe"], "score": [1, 2, 3, 4]}
        )
        neutralized = neutralize_csv_frame(frame)
        assert neutralized["formula"].tolist() == ["'=1+1", "' =1+1", "'\t@cmd", "safe"]
        assert neutralized["score"].tolist() == [1, 2, 3, 4]

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
