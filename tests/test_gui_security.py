"""Security tests for the prototyping GUI command runner."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


class TestGuiCommandSafety:
    """GUI subprocess helpers must not accept attacker-controlled argv."""

    def test_demo_allowlist_is_closed(self):
        expected = {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        }
        assert expected == ALLOWED_DEMO_MODES
        assert "; rm -rf /" not in ALLOWED_DEMO_MODES
        assert "--setup" not in ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_string_argv(self):
        status, output = _run_command("python -c 'pass'")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_nested_or_non_string_items(self):
        status, output = _run_command(["python", ["-c", "pass"]])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output
