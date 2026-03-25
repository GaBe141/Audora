"""Security-focused tests for GUI mutation guardrails."""

import importlib

from gui import app as gui_app


def test_gui_mutation_flag_defaults_disabled():
    """Mutating GUI actions should default to disabled unless explicitly enabled."""
    assert gui_app.GUI_MUTATIONS_ENABLED is False


def test_run_action_blocked_when_mutations_disabled():
    """Command execution callback should be blocked when security mode is active."""
    status, output = gui_app.run_action(None, None, None, None, "statistical")
    assert status == "Blocked"
    assert "disabled by default for security" in output

