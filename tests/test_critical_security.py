"""Regression tests for critical cache, webhook, CSV, and command hardening."""

import importlib
import os
import pickle
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from core.caching import RedisCacheBackend, dumps_signed, loads_signed
from core.config import SecureConfig
from core.exceptions import APIConnectionError
from core.notification_service import EnhancedNotificationService
from core.utils import confine_export_path, neutralize_csv_dataframe
from integrations.lastfm_integration import BASE_URL, LastFmAPI
from scripts.fix_linting_issues import run_command


class TestSignedCache:
    """HMAC-signed JSON cache payloads reject pickle and unsigned bytes."""

    def test_round_trip_supports_datetime_tuple_and_dataframe(self):
        key = b"test-signing-key"
        frame = pd.DataFrame({"name": ["track"], "score": [1]})
        original = {
            "when": datetime(2026, 1, 2, 3, 4, 5),
            "pair": (1, "two"),
            "frame": frame,
        }
        loaded = loads_signed(dumps_signed(original, key), key)
        assert loaded["when"] == original["when"]
        assert loaded["pair"] == original["pair"]
        assert loaded["frame"].iloc[0]["name"] == "track"
        assert loaded["frame"].iloc[0]["score"] == 1

    def test_rejects_pickle_and_bad_signature(self):
        key = b"test-signing-key"
        with pytest.raises(ValueError, match="pickle|unsigned"):
            loads_signed(pickle.dumps({"a": 1}), key)
        signed = bytearray(dumps_signed({"a": 1}, key))
        signed[-2] = signed[-2] ^ 1
        with pytest.raises(ValueError, match="signature|payload|envelope"):
            loads_signed(bytes(signed), key)

    def test_rejected_redis_payload_is_deleted(self):
        class _Client:
            def __init__(self) -> None:
                self.store = {"bad": b"\x80\x04not-json"}
                self.deleted: list[str] = []

            def get(self, key: str) -> bytes | None:
                return self.store.get(key)

            def delete(self, key: str) -> None:
                self.deleted.append(key)
                self.store.pop(key, None)

        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        backend._client = _Client()
        assert backend.get("bad") is None
        assert backend._client.deleted == ["bad"]

    def test_clear_scans_prefix_instead_of_flushing_database(self):
        class _Client:
            def __init__(self) -> None:
                self.deleted: list[bytes] = []
                self.flushed = False

            def scan(self, cursor: int = 0, match: str | None = None, count: int = 0):
                assert match == "audora:*"
                return 0, [b"audora:one"]

            def delete(self, *keys: bytes) -> int:
                self.deleted.extend(keys)
                return len(keys)

            def flushdb(self) -> None:
                self.flushed = True

        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._key_prefix = "audora"
        backend._client = _Client()
        backend.clear()
        assert backend._client.deleted == [b"audora:one"]
        assert backend._client.flushed is False


class TestWebhookHardening:
    """Webhook targets reject SSRF bypasses that still look like public URLs."""

    def test_rejects_credentials_obfuscation_metadata_and_mapped_addresses(self):
        svc = EnhancedNotificationService()
        blocked = [
            "https://user:secret@example.com/hook",
            "https://2130706433/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f000001/hook",
            "https://127.1/hook",
            "https://metadata.google.internal/hook",
            "https://foo.localhost/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://169.254.169.254/latest",
            "https://127.0.0.1/hook",
        ]
        for url in blocked:
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_config_path_cannot_escape_config_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="config directory"):
            svc.save_config(str(tmp_path / "notification_config.json"))


class TestCsvAndLastFm:
    """CSV exports and Last.fm requests fail closed."""

    def test_string_dtype_formula_is_neutralized(self):
        frame = pd.DataFrame({"track": ["=1+1", "safe"]}, dtype="string")
        sanitized = neutralize_csv_dataframe(frame)
        assert sanitized.iloc[0]["track"] == "'=1+1"
        assert sanitized.iloc[1]["track"] == "safe"

    def test_export_path_stays_inside_exports(self, tmp_path):
        root = tmp_path / "exports"
        with pytest.raises(ValueError, match="exports"):
            confine_export_path("../outside.csv", root)
        destination = confine_export_path("report.csv", root)
        assert destination.parent == root.resolve()

    def test_export_to_csv_neutralizes_formula_text(self, data_store):
        with data_store.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO trends (
                    platform, track_id, track_name, artist, score, rank, region,
                    trend_date, first_detected, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "spotify",
                    "track-1",
                    "=1+1",
                    "Artist",
                    1.0,
                    1,
                    "global",
                    "2026-01-01",
                    "2026-01-01",
                    "2026-01-01",
                ),
            )
            conn.commit()
        exported = Path(data_store.export_to_csv("trends", "trends.csv"))
        contents = exported.read_text(encoding="utf-8")
        assert "'=1+1" in contents
        with pytest.raises(ValueError, match="exports"):
            data_store.export_to_csv("trends", "../outside.csv")

    def test_lastfm_disables_redirects_and_rejects_http_status(self):
        assert BASE_URL.startswith("https://")
        api = LastFmAPI(api_key="test_key")
        assert api.session.trust_env is False
        mock_response = MagicMock()
        mock_response.is_redirect = False
        mock_response.status_code = 200
        mock_response.json.return_value = {"artists": {"artist": []}}
        with patch.object(api.session, "get", return_value=mock_response) as get:
            api.get_top_artists_global(limit=1)
        assert get.call_args.args[0] == BASE_URL
        assert get.call_args.kwargs["allow_redirects"] is False

        mock_response.is_redirect = True
        with patch.object(api.session, "get", return_value=mock_response):
            with pytest.raises(APIConnectionError, match="redirects"):
                api.get_top_artists_global(limit=1)

    def test_dotenv_does_not_override_process_environment(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AUDORA_DOTENV_GUARD", "from-process")
        env_file = tmp_path / ".env"
        env_file.write_text("AUDORA_DOTENV_GUARD=from-file\n", encoding="utf-8")
        SecureConfig(env_file=env_file)
        assert os.environ["AUDORA_DOTENV_GUARD"] == "from-process"


class TestCommandAndGuiGuards:
    """Demo arguments and lint helper commands cannot reach a shell."""

    def test_lint_helper_runs_argv_without_shell(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["shell"] = kwargs.get("shell")

            class _Result:
                stderr = ""

            return _Result()

        monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)

        assert run_command(["python", "-c", "pass"], "demo") is True
        assert captured["shell"] is False
        assert captured["cmd"] == ["python", "-c", "pass"]

    def test_gui_rejects_unexpected_demo_and_formula_csv(self, monkeypatch):
        gui_module = importlib.import_module("gui.app")

        class _Ctx:
            triggered_id = "btn-demo"

        monkeypatch.setattr(gui_module, "ctx", _Ctx())
        status, output = gui_module.run_action(None, 1, None, None, "statistical;touch /tmp/pwned")
        assert status == "Error"
        assert output == "Unsupported demo mode"

        saved = gui_module.save_settings(
            1,
            "https://127.0.0.1/hook",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert "private or restricted" in saved

        download = gui_module.export_csv(1, [{"track_name": "=1+1", "artist": "A"}])
        content = download["content"]
        assert "'=1+1" in content
