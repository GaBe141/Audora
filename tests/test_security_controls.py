"""Tests for critical cache, webhook, export, and CSV hardening."""

import json
from datetime import datetime

import pandas as pd
import pytest

from core.caching import dumps_signed, loads_signed
from core.data_store import EnhancedMusicDataStore
from core.notification_service import EnhancedNotificationService, _html_email_document
from core.utils import neutralize_dataframe_for_csv


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
