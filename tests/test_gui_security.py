"""Security tests for GUI subprocess orchestration."""

import importlib

gui_app = importlib.import_module("gui.app")
ALLOWED_DEMO_MODES = gui_app.ALLOWED_DEMO_MODES
_run_command = gui_app._run_command


def test_demo_allowlist_matches_cli_choices():
    expected = frozenset({"statistical", "trending", "multi_source", "platform", "all"})
    assert expected == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command([123, "main.py"])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_in_arguments():
    status, output = _run_command(["python", "main.py\x00--demo"])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_action_rejects_unknown_demo_mode(monkeypatch):
    monkeypatch.setattr(gui_app, "ctx", type("Ctx", (), {"triggered_id": "btn-demo"})())
    status, output = gui_app.run_action(1, 1, None, None, "rm -rf /")
    assert status == "Error"
    assert "Invalid demo mode" in output
