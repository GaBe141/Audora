"""Security tests for the optional Dash GUI."""

import importlib
import sys

import pytest

pytest.importorskip("dash")

gui_app = importlib.import_module("gui.app")


def test_gui_command_execution_disabled_by_default(monkeypatch):
    monkeypatch.delenv(gui_app.GUI_COMMANDS_ENV, raising=False)

    status, output = gui_app._run_command([sys.executable, "-c", "print('should not run')"])

    assert status == "Disabled"
    assert gui_app.GUI_COMMANDS_ENV in output
    assert "should not run" not in output
