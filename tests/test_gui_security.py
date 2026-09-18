"""Security tests for GUI command allowlisting."""

import sys
from unittest.mock import MagicMock, patch

import pytest

dash = pytest.importorskip("dash")

from gui.app import (  # noqa: E402
    ALLOWED_DEMO_MODES,
    MAIN_PY,
    _run_command,
    run_action,
)


def test_run_command_rejects_non_allowlisted_payloads():
    status, output = _run_command(["/bin/sh", "-c", "id"])
    assert status == "Error"
    assert "interpreter" in output.lower() or "not allowed" in output.lower()

    status, output = _run_command([sys.executable, str(MAIN_PY), "--demo", "rm -rf /"])
    assert status == "Error"
    assert "arguments" in output.lower()


def test_run_command_invokes_allowlisted_main(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0

        def communicate(self, timeout=None):
            return "ok", None

        def kill(self):
            return None

    def fake_popen(args, **kwargs):
        captured["args"] = args
        return FakeProc()

    monkeypatch.setattr(sys.modules["gui.app"].subprocess, "Popen", fake_popen)
    status, output = _run_command([sys.executable, str(MAIN_PY), "--setup"])
    assert status.startswith("Done")
    assert captured["args"][0] == sys.executable
    assert captured["args"][1] == str(MAIN_PY)
    assert captured["args"][2:] == ["--setup"]


def test_run_action_rejects_unknown_demo_mode():
    fake_ctx = MagicMock()
    fake_ctx.triggered_id = "btn-demo"
    with patch("gui.app.ctx", fake_ctx):
        status, output = run_action(1, 1, 0, 0, "not-a-demo")
    assert status == "Error"
    assert "demo" in output.lower()
    assert "not-a-demo" not in ALLOWED_DEMO_MODES
