"""Focused tests for critical security controls."""

import asyncio
import importlib
import smtplib
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock

import pandas as pd
import pytest

from core.config import SecureConfig
from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    _PinnedResolver,
)
from core.utils import confine_export_path, neutralize_csv_dataframe


def test_dotenv_does_not_override_process_environment(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SPOTIFY_CLIENT_ID=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "from-env")
    mocked = MagicMock()
    monkeypatch.setattr("core.config.load_dotenv", mocked)
    SecureConfig(env_file=env_file)
    assert mocked.call_args.kwargs["override"] is False


def test_csv_export_neutralizes_string_dtype_and_confines_paths():
    frame = pd.DataFrame({"name": ["=cmd|'/c calc'!A0", "ok"]})
    frame["name"] = frame["name"].astype("string")
    cleaned = neutralize_csv_dataframe(frame)
    assert str(cleaned.iloc[0]["name"]).startswith("'")
    assert cleaned.iloc[1]["name"] == "ok"

    with pytest.raises(ValueError, match="exports"):
        confine_export_path("/tmp/audora-escape.csv", roots=("exports",), create_dirs=False)

    confined = confine_export_path("exports/audora_trends.csv", create_dirs=False)
    assert confined.parent.name == "exports"


def test_lint_fixer_runs_argument_lists(monkeypatch):
    fixer = importlib.import_module("scripts.fix_linting_issues")
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0)

    monkeypatch.setattr(fixer.subprocess, "run", fake_run)
    assert fixer.run_command(["python3", "-m", "pip", "--version"], "demo") is True
    assert captured["kwargs"]["shell"] is False
    assert isinstance(captured["cmd"], list)


def test_email_always_verifies_tls_and_strips_header_injection(monkeypatch):
    svc = EnhancedNotificationService()
    svc.config["email"].update(
        {
            "smtp_server": "smtp.example.com",
            "port": 587,
            "use_tls": False,
            "username": "",
            "password": "",
            "recipients": ["listener@example.com"],
            "from_address": "alerts@example.com",
        }
    )
    seen: dict = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            seen["host"] = host
            seen["port"] = port

        def ehlo(self):
            return None

        def starttls(self, context=None):
            seen["context"] = context

        def send_message(self, msg: MIMEMultipart):
            seen["message"] = msg

        def quit(self):
            return None

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    message = NotificationMessage(
        title="Hello\r\nBcc: attacker@evil.com",
        content="<script>alert(1)</script>",
        priority=NotificationPriority.LOW,
        channels=[NotificationChannel.EMAIL],
        attachments=["/etc/passwd"],
    )
    result = asyncio.run(svc._send_email(message))
    assert result["success"] is True
    assert seen["context"] is not None
    assert seen["context"].verify_mode.name == "CERT_REQUIRED"
    rendered = seen["message"].as_string()
    assert "\nBcc:" not in rendered
    assert "&lt;script&gt;" in rendered
    assert len(seen["message"].get_payload()) == 2


def test_pinned_resolver_refuses_unvalidated_hosts():
    async def _check() -> None:
        resolver = _PinnedResolver("hooks.example", ["1.2.3.4"])
        pinned = await resolver.resolve("hooks.example", 443)
        assert pinned[0]["host"] == "1.2.3.4"
        with pytest.raises(OSError):
            await resolver.resolve("127.0.0.1", 443)

    asyncio.run(_check())


def test_gui_demo_mode_is_allowlisted(monkeypatch):
    gui_module = importlib.import_module("gui.app")

    class FakeCtx:
        triggered_id = "btn-demo"

    monkeypatch.setattr(gui_module, "ctx", FakeCtx())
    called: dict = {}

    def fake_run(args):
        called["args"] = args
        return "Done", "ok"

    monkeypatch.setattr(gui_module, "_run_command", fake_run)
    status, output = gui_module.run_action(None, 1, None, None, "statistical;touch /tmp/pwned")
    assert status == "Error"
    assert "Unsupported" in output
    assert "args" not in called

    status, output = gui_module.run_action(None, 1, None, None, "trending")
    assert status == "Done"
    assert called["args"][-1] == "trending"

    download = gui_module.export_csv(1, [{"track": "=1+1", "artist": "ok"}])
    content = download["content"]
    assert content.startswith("'=1+1") or "'=1+1" in content
