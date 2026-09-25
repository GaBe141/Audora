"""Tests for critical cache, webhook, export, and redirect protections."""

import json
from pathlib import Path

import pandas as pd
import pytest

from core.caching import deserialize_signed_json, serialize_signed_json
from core.config import SecureConfig
from core.notification_service import EnhancedNotificationService
from core.security_utils import (
    confine_project_path,
    ip_policy,
    is_subreddit,
    neutralize_csv_dataframe,
    neutralize_csv_text,
    validate_smtp_target,
)


class TestSignedJsonCache:
    def test_round_trip_and_dataframe(self):
        key = b"test-signing-key"
        payload = {"artist": "Ada", "score": 1}
        raw = serialize_signed_json(payload, key)
        assert deserialize_signed_json(raw, key) == payload

        frame = pd.DataFrame([{"artist": "=1+1", "score": 2}])
        restored = deserialize_signed_json(serialize_signed_json(frame, key), key)
        assert list(restored["artist"]) == ["=1+1"]

    def test_rejects_pickle_envelope_and_tampering(self):
        key = b"test-signing-key"
        legacy = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "abc", "payload": "cGlja2xl"}
        ).encode()
        assert deserialize_signed_json(legacy, key) is None

        raw = bytearray(serialize_signed_json({"ok": True}, key))
        raw[-2] = raw[-2] ^ 1
        assert deserialize_signed_json(bytes(raw), key) is None


class TestWebhookAndSmtpGuards:
    def test_blocks_loopback_and_mapped_loopback_when_private_is_allowed(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://127.0.0.1/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://169.254.169.254/latest", allow_private=True)

    def test_rejects_userinfo_and_non_standard_port(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="port 443"):
            svc._validate_webhook_url("https://example.com:8443/hook")

    def test_smtp_rejects_localhost_and_odd_ports(self):
        with pytest.raises(ValueError, match="Localhost"):
            validate_smtp_target("localhost", 587)
        with pytest.raises(ValueError, match="Localhost"):
            validate_smtp_target("127.0.0.1", 465)
        with pytest.raises(ValueError, match="465 or 587"):
            validate_smtp_target("smtp.example.com", 25)

    def test_mapped_private_address_is_not_treated_as_public(self):
        assert ip_policy("::ffff:10.1.2.3") == "private"
        assert ip_policy("::ffff:127.0.0.1") == "blocked"


class TestExportGuards:
    def test_csv_neutralizes_formula_prefixes_and_leading_whitespace(self):
        assert neutralize_csv_text("=1+1").startswith("'")
        assert neutralize_csv_text(" =1+1").startswith("'")
        assert neutralize_csv_text("\t@cmd").startswith("'")
        frame = neutralize_csv_dataframe(pd.DataFrame({"artist": ["=cmd", "Ada"]}))
        assert frame.iloc[0]["artist"] == "'=cmd"
        assert frame.iloc[1]["artist"] == "Ada"

    def test_export_path_cannot_leave_the_project(self):
        with pytest.raises(ValueError, match="project"):
            confine_project_path("/tmp/audora-escape.csv")
        inside = confine_project_path("data/safe-export.csv")
        assert inside.is_relative_to(Path(__file__).resolve().parent.parent)

    def test_subreddit_names_cannot_change_the_request_path(self):
        assert is_subreddit("Music")
        assert not is_subreddit("../api")
        assert not is_subreddit("a/b")
        assert not is_subreddit("name?x=1")


class TestRedirectUri:
    def test_rejects_lookalike_localhost_host(self, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "\n".join(
                [
                    "SPOTIFY_CLIENT_ID=client",
                    "SPOTIFY_CLIENT_SECRET=secret",
                    "SPOTIFY_REDIRECT_URI=http://localhost.evil.com/callback",
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.delenv("SPOTIFY_CLIENT_ID", raising=False)
        monkeypatch.delenv("SPOTIFY_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SPOTIFY_REDIRECT_URI", raising=False)
        config = SecureConfig(env_file=str(env_file))
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            config.get_spotify_config()
