"""Security tests for Dash GUI command execution."""

import subprocess

from gui import app as gui_app


def test_run_command_blocked_by_default(monkeypatch):
    """GUI subprocess actions require explicit opt-in."""
    monkeypatch.delenv("AUDORA_ENABLE_GUI_ACTIONS", raising=False)

    status, output = gui_app._run_command(["python", "--version"])

    assert status == "Blocked"
    assert "AUDORA_ENABLE_GUI_ACTIONS" in output


def test_run_command_requires_allowlisted_demo():
    """Unexpected demo values should not be turned into command arguments."""
    assert gui_app.DEMO_COMMANDS.get("statistical; rm -rf /") is None


def test_run_command_executes_when_explicitly_enabled(monkeypatch):
    """Trusted localhost sessions can still opt in to command execution."""
    calls = []

    class FakeProcess:
        returncode = 0

        def communicate(self, timeout):
            return ("ok", None)

        def kill(self):
            raise AssertionError("kill should not be called")

    def fake_popen(args, **kwargs):
        calls.append((args, kwargs))
        return FakeProcess()

    monkeypatch.setenv("AUDORA_ENABLE_GUI_ACTIONS", "1")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    status, output = gui_app._run_command(["python", "--version"])

    assert status == "Done (exit 0)"
    assert output == "ok"
    assert calls[0][0] == ["python", "--version"]
