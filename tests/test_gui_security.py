"""Security tests for GUI subprocess allowlisting."""

import sys
from pathlib import Path

from gui.app import ALLOWED_DEMO_MODES, PROJECT_ROOT, _run_command, run_action


def test_run_command_rejects_non_main_payload():
    status, output = _run_command([sys.executable, "-c", "print('nope')"])
    assert status == "Error"
    assert "allowlisted" in output


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command([sys.executable, str(PROJECT_ROOT / "main.py"), 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_demo_modes_are_strictly_allowlisted():
    assert ALLOWED_DEMO_MODES == {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }


def test_run_action_rejects_unknown_demo_mode(monkeypatch):
    class _Triggered:
        triggered_id = "btn-demo"

    monkeypatch.setattr("gui.app.ctx", _Triggered)
    status, output = run_action(1, 1, 0, 0, "not-a-real-demo; rm -rf /")
    assert status == "Error"
    assert output == "Invalid demo mode"


def test_run_action_allowlisted_demo_invokes_main(monkeypatch):
    captured: dict = {}

    def _fake_run(args: list[str]) -> tuple[str, str]:
        captured["args"] = args
        return "Done (exit 0)", "ok"

    class _Triggered:
        triggered_id = "btn-demo"

    monkeypatch.setattr("gui.app.ctx", _Triggered)
    monkeypatch.setattr("gui.app._run_command", _fake_run)
    status, output = run_action(0, 1, 0, 0, "statistical")
    assert status == "Done (exit 0)"
    assert captured["args"] == [
        sys.executable,
        str(Path(PROJECT_ROOT) / "main.py"),
        "--demo",
        "statistical",
    ]
