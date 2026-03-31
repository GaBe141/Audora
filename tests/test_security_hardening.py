"""Security hardening tests for critical-risk controls."""

import base64
import hashlib
import hmac
import json
import pickle

import pandas as pd
import pytest

from core.caching import RedisCacheBackend
from gui.app import app as dash_app
from run_gui import _validate_gui_security_policy


def _make_test_backend(signing_key: bytes = b"test-signing-key") -> RedisCacheBackend:
    """Create RedisCacheBackend instance for codec tests without Redis connection."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = signing_key  # type: ignore[attr-defined]
    return backend


class TestRedisCacheSerializationSecurity:
    """Tests for secure Redis cache serialization behavior."""

    def test_rejects_legacy_pickle_envelope(self):
        backend = _make_test_backend()

        pickle_payload = pickle.dumps({"danger": "legacy"})
        signature = hmac.new(backend._signing_key, pickle_payload, hashlib.sha256).hexdigest()
        legacy_envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": base64.b64encode(pickle_payload).decode("ascii"),
        }
        raw = json.dumps(legacy_envelope).encode("utf-8")

        assert backend._deserialize(raw) is None

    def test_round_trip_dataframe_and_nested_scalars(self):
        backend = _make_test_backend()
        value = {
            "stats": {"count": 2, "ok": True},
            "rows": [
                {"track": "Song A", "score": 91.2},
                {"track": "Song B", "score": 88.4},
            ],
            "df": pd.DataFrame([{"platform": "tiktok", "score": 10.0}]),
        }

        raw = backend._serialize(value)
        decoded = backend._deserialize(raw)

        assert isinstance(decoded, dict)
        assert decoded["stats"]["count"] == 2
        assert decoded["rows"][0]["track"] == "Song A"
        assert isinstance(decoded["df"], pd.DataFrame)
        assert list(decoded["df"]["platform"]) == ["tiktok"]


class TestGuiAuthMiddleware:
    """Tests for GUI HTTP basic-auth protection."""

    def _client(self):
        return dash_app.server.test_client()

    def _auth_header(self, username: str, password: str) -> dict[str, str]:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def test_requires_auth_when_enabled(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "1")
        monkeypatch.setenv("AUDORA_GUI_USERNAME", "admin")
        monkeypatch.setenv("AUDORA_GUI_PASSWORD", "secret")

        response = self._client().get("/")
        assert response.status_code == 401
        assert "Basic realm=" in response.headers.get("WWW-Authenticate", "")

    def test_rejects_wrong_credentials(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "1")
        monkeypatch.setenv("AUDORA_GUI_USERNAME", "admin")
        monkeypatch.setenv("AUDORA_GUI_PASSWORD", "secret")

        response = self._client().get("/", headers=self._auth_header("admin", "wrong"))
        assert response.status_code == 401

    def test_allows_valid_credentials(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "1")
        monkeypatch.setenv("AUDORA_GUI_USERNAME", "admin")
        monkeypatch.setenv("AUDORA_GUI_PASSWORD", "secret")

        response = self._client().get("/", headers=self._auth_header("admin", "secret"))
        assert response.status_code == 200

    def test_fail_closed_when_enabled_without_credentials(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "1")
        monkeypatch.delenv("AUDORA_GUI_USERNAME", raising=False)
        monkeypatch.delenv("AUDORA_GUI_PASSWORD", raising=False)

        response = self._client().get("/")
        assert response.status_code == 503


class TestGuiRemoteBindingPolicy:
    """Tests for secure host-binding validation in run_gui entrypoint."""

    def test_loopback_host_allowed_without_extra_flags(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AUDORA_GUI_ALLOW_REMOTE", raising=False)
        monkeypatch.delenv("AUDORA_GUI_REQUIRE_AUTH", raising=False)
        _validate_gui_security_policy("127.0.0.1")

    def test_remote_host_blocked_without_explicit_opt_in(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("AUDORA_GUI_ALLOW_REMOTE", raising=False)
        with pytest.raises(RuntimeError, match="AUDORA_GUI_ALLOW_REMOTE"):
            _validate_gui_security_policy("0.0.0.0")

    def test_remote_host_requires_auth_and_credentials(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AUDORA_GUI_ALLOW_REMOTE", "1")
        monkeypatch.setenv("AUDORA_GUI_REQUIRE_AUTH", "1")
        monkeypatch.setenv("AUDORA_GUI_USERNAME", "admin")
        monkeypatch.setenv("AUDORA_GUI_PASSWORD", "secret")
        _validate_gui_security_policy("0.0.0.0")
