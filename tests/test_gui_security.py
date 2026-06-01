"""Security tests for the optional Dash GUI."""

import sys

import pytest

pytest.importorskip("dash")

from gui import app as gui_app  # noqa: E402


def test_gui_command_execution_disabled_by_default(monkeypatch):
    monkeypatch.delenv(gui_app.GUI_COMMANDS_ENV, raising=False)

    status, output = gui_app._run_command([sys.executable, "-c", "print('should not run')"])

    assert status == "Disabled"
    assert gui_app.GUI_COMMANDS_ENV in output
    assert "should not run" not in output
