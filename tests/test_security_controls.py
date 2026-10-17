"""Tests for critical cache, SSRF, redirect, and CSV protections."""

import base64
import inspect
import json

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from core.config import validate_spotify_redirect_uri
from core.notification_service import EnhancedNotificationService
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
            "http://127.0.0.1:8888/callback#fragment",
            "http://127.0.0.1:8888/callback\r\n",
            "http://127.0.0.1:8888/call\\back",
            "http://2130706433/callback",
            "http://0177.0.0.1/callback",
            "http://0x7f.0.0.1/callback",
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
            "https://[::10.0.0.1]/hook",
            "https://[::127.0.0.1]/hook",
            "https://[::169.254.169.254]/hook",
            "https://[::ffff:0:10.0.0.1]/hook",
            "https://[::ffff:0:8.8.8.8]/hook",
            "https://[5f00::1]/hook",
            "https://[fd00::1]/hook",
            "https://240.0.0.1/hook",
            "https://example.com\\@127.0.0.1/hook",
            "https://example.com/hook\r\nX-Injected: 1",
            "https://example.com/hook\x7f",
        )
        for url in blocked:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_mapped_public_addresses_stay_public(self):
        svc = EnhancedNotificationService()
        assert svc._is_always_blocked_ip("::ffff:8.8.8.8") is False
        assert svc._is_restricted_ip("::ffff:8.8.8.8") is False
        assert svc._is_always_blocked_ip("::ffff:10.0.0.1") is False
        assert svc._is_rfc1918("::ffff:10.0.0.1") is True
        assert svc._is_always_blocked_ip("::10.0.0.1") is True
        assert svc._is_always_blocked_ip("::ffff:0:10.0.0.1") is True
        assert svc._is_always_blocked_ip("5f00::1") is True

    def test_email_headers_and_attachment_names_reject_controls(self):
        svc = EnhancedNotificationService()
        assert svc._safe_header("Audora alert", "subject") == "Audora alert"
        with pytest.raises(ValueError):
            svc._safe_header("ok\r\nBcc: a@b.c", "subject")
        with pytest.raises(ValueError):
            svc._safe_header("ok\x7f", "subject")
        assert svc._safe_attachment_name("report.csv") == "report.csv"
        with pytest.raises(ValueError):
            svc._safe_attachment_name("report\r\nBcc: a@b.c.csv")

    def test_implicit_tls_verifies_certificates(self):
        source = inspect.getsource(EnhancedNotificationService._send_email)
        assert "SMTP_SSL(context=ssl.create_default_context(), timeout=30)" in source

    def test_private_webhook_opt_in_still_allows_rfc1918(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=False)

    def test_smtp_blocks_private_and_teredo_addresses(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("10.0.0.1", 587)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("2001::1", 587)


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
