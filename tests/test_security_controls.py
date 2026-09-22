"""Regression tests for critical security controls."""

import json
import pickle
from datetime import datetime

import pandas as pd
import pytest

from core.caching import dumps_signed, loads_signed
from core.notification_service import EnhancedNotificationService
from core.utils import confine_to_project, neutralize_csv_formula, neutralize_dataframe


class TestSignedCachePayloads:
    """Redis cache values must be signed JSON, never pickle."""

    def test_round_trip_datetime_tuple_and_dataframe(self):
        frame = pd.DataFrame({"track": ["Song"], "score": [1.5]})
        original = {
            "when": datetime(2026, 9, 22, 1, 2, 3),
            "pair": ("a", 1),
            "frame": frame,
        }
        key = b"test-signing-key"
        restored = loads_signed(dumps_signed(original, key), key)
        assert restored["when"] == original["when"]
        assert restored["pair"] == original["pair"]
        assert restored["frame"].iloc[0]["track"] == "Song"

    def test_rejects_pickle_payload(self):
        raw = pickle.dumps({"cmd": "os.system"})
        with pytest.raises(ValueError, match="pickle"):
            loads_signed(raw, b"test-signing-key")

    def test_rejects_unsigned_json(self):
        raw = json.dumps({"v": 2, "payload": "e30="}).encode()
        with pytest.raises(ValueError, match="pickle|unsigned|signature"):
            loads_signed(raw, b"test-signing-key")

    def test_rejects_tampered_signature(self):
        key = b"test-signing-key"
        envelope = json.loads(dumps_signed({"ok": True}, key))
        envelope["sig"] = "0" * len(envelope["sig"])
        raw = json.dumps(envelope).encode()
        with pytest.raises(ValueError, match="signature"):
            loads_signed(raw, key)


class TestWebhookValidation:
    """Webhook targets must be public HTTPS URLs without bypass tricks."""

    def test_rejects_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:secret@example.com/hook")

    def test_rejects_decimal_ip_literal(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Obfuscated"):
            svc._validate_webhook_url("https://2130706433/hook")

    def test_rejects_ipv4_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="IPv4-mapped"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook")

    def test_rejects_localhost_suffix_and_metadata_host(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://app.localhost/hook")
        with pytest.raises(ValueError, match="metadata or internal"):
            svc._validate_webhook_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_still_rejects_private_literals_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.1.2.3/hook")


class TestCsvExportSafety:
    """Spreadsheet exports must not carry formula payloads or escape the project."""

    def test_formula_cells_are_prefixed(self):
        frame = neutralize_dataframe(
            pd.DataFrame({"name": ["=cmd()", " safe", "+1", "@sum"], "score": [1, 2, 3, 4]})
        )
        assert list(frame["name"]) == ["'=cmd()", " safe", "'+1", "'@sum"]
        assert list(frame["score"]) == [1, 2, 3, 4]

    def test_neutralize_csv_formula_ignores_numbers(self):
        assert neutralize_csv_formula(-1) == -1
        assert neutralize_csv_formula("album") == "album"

    def test_confine_to_project_rejects_escape(self):
        with pytest.raises(ValueError, match="outside the project"):
            confine_to_project("/tmp/audora-export.csv", allowed_suffixes=(".csv",))
