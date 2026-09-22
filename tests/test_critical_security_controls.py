"""Tests for critical cache, export, email, and GUI input protections."""

import asyncio
import importlib
import json
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import pandas as pd
import pytest

from core.caching import dumps_signed, loads_signed
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from core.utils import neutralize_csv_formulas


class TestSignedCachePayloads:
    """Redis cache values must be signed JSON, never pickle."""

    def test_round_trip_json_types(self):
        key = b"0123456789abcdef"
        frame = pd.DataFrame({"name": ["alpha"], "score": [1]})
        original = {
            "when": datetime(2026, 1, 2, 3, 4, 5),
            "pair": ("a", 1),
            "frame": frame,
        }
        restored = loads_signed(dumps_signed(original, key), key)
        assert restored["when"] == original["when"]
        assert restored["pair"] == original["pair"]
        assert restored["frame"].iloc[0]["name"] == "alpha"

    def test_rejects_pickle_and_unsigned_bytes(self):
        key = b"0123456789abcdef"
        with pytest.raises(ValueError, match="pickle or unsigned"):
            loads_signed(b"\x80\x04\x95\x05\x00", key)
        with pytest.raises(ValueError, match="invalid serialization envelope"):
            loads_signed(b'{"v": 1, "payload": "abc"}', key)

    def test_rejects_tampered_signature(self):
        key = b"0123456789abcdef"
        envelope = json.loads(dumps_signed({"ok": True}, key))
        envelope["sig"] = "0" * len(envelope["sig"])
        with pytest.raises(ValueError, match="invalid signature"):
            loads_signed(json.dumps(envelope).encode("utf-8"), key)


class TestCsvExportSafety:
    """Exports stay inside the exports directory and cannot start formulas."""

    def test_string_dtype_formulas_are_neutralized(self):
        frame = pd.DataFrame({"name": pd.Series(["=1+1", "ok"], dtype="string")})
        cleaned = neutralize_csv_formulas(frame)
        assert cleaned.iloc[0]["name"] == "'=1+1"
        assert cleaned.iloc[1]["name"] == "ok"

    def test_export_rejects_paths_outside_exports(self, data_store, tmp_path):
        with pytest.raises(ValueError, match="exports"):
            data_store.export_to_csv("trends", str(tmp_path.parent / "outside.csv"))

    def test_export_prefixes_formula_cells(self, data_store, sample_trends):
        sample_trends[0].track_name = "=cmd|' /C calc'!A0"
        data_store.save_trends_bulk(sample_trends)
        exported = data_store.export_to_csv("trends", "trends.csv")
        contents = Path(exported).read_text(encoding="utf-8")
        assert "'=cmd|" in contents


class TestEmailHardening:
    """SMTP uses verified TLS and cannot be steered with header breaks."""

    def test_strips_header_injection_and_escapes_html(self, monkeypatch):
        sent: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                sent["host"] = host
                sent["port"] = port

            def ehlo(self):
                return None

            def starttls(self, context=None):
                sent["context"] = context

            def login(self, user, password):
                return None

            def send_message(self, msg: MIMEMultipart):
                sent["subject"] = msg["Subject"]
                sent["parts"] = len(msg.get_payload())
                html_part = msg.get_payload()[1]
                sent["html"] = html_part.get_payload(decode=True).decode()

            def quit(self):
                return None

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        svc = EnhancedNotificationService()
        svc.config["email"] = {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "alerts@example.com",
            "recipients": ["listener@example.com"],
        }
        message = NotificationMessage(
            title="Hello\r\nBcc: evil@example.com",
            content="<script>alert(1)</script>",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
            attachments=["/etc/passwd"],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert sent["subject"] == "HelloBcc: evil@example.com"
        assert isinstance(sent["context"], ssl.SSLContext)
        assert "<script>" not in str(sent["html"])
        assert sent["parts"] == 2


class TestWebhookPostSafety:
    """Outbound webhooks must not follow redirects or honor proxy environment variables."""

    def test_post_disables_redirects_and_proxy_env(self, monkeypatch):
        created: dict[str, object] = {}

        class FakeResponse:
            status = 200

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        class FakeSession:
            def __init__(self, *args, **kwargs):
                created["session_kwargs"] = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            def post(self, url, **kwargs):
                created["url"] = url
                created["post_kwargs"] = kwargs
                return FakeResponse()

        monkeypatch.setattr("core.notification_service.aiohttp.ClientSession", FakeSession)
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
        svc = EnhancedNotificationService()
        message = NotificationMessage(
            title="ping",
            content="pong",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.WEBHOOK],
        )
        svc.config["webhook"]["url"] = "https://10.0.0.1/hook"
        result = asyncio.run(svc._send_webhook(message))
        assert result["success"] is True
        assert created["session_kwargs"]["trust_env"] is False
        assert created["post_kwargs"]["allow_redirects"] is False
        assert created["url"] == "https://10.0.0.1/hook"


class TestGuiInputGuards:
    """Dashboard actions must ignore unexpected demo names and unsafe webhook URLs."""

    def test_demo_allowlist_blocks_unexpected_values(self, monkeypatch):
        gui_app = importlib.import_module("gui.app")

        class FakeCtx:
            triggered_id = "btn-demo"

        monkeypatch.setattr(gui_app, "ctx", FakeCtx())
        status, output = gui_app.run_action(0, 1, 0, 0, "statistical;touch /tmp/pwned")
        assert status == "Error"
        assert "Unsupported demo" in output

    def test_csv_export_neutralizes_formula_rows(self):
        from gui.app import export_csv

        result = export_csv(1, [{"track_name": "=1+1", "score": 3}])
        assert "'=1+1" in result["content"]

    def test_save_settings_rejects_loopback_webhook(self, monkeypatch, tmp_path):
        from gui.app import save_settings

        monkeypatch.chdir(tmp_path)
        result = save_settings(
            1,
            None,
            None,
            "https://127.0.0.1/hook",
            None,
            None,
            None,
            None,
        )
        assert result.startswith("Error")
        assert not (tmp_path / "config" / "notification_config.json").exists()


def test_config_path_cannot_escape_config_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = EnhancedNotificationService()
    with pytest.raises(ValueError, match="config directory"):
        svc.save_config(str(tmp_path / "notification_config.json"))
