"""Security tests for GUI command orchestration."""

from gui.app import ALLOWED_DEMO_MODES, _demo_command, _run_command


class TestGuiCommandHardening:
    """GUI subprocess helpers must reject untrusted arguments."""

    def test_demo_modes_are_allowlisted(self):
        assert "statistical" in ALLOWED_DEMO_MODES
        assert "--setup" not in ALLOWED_DEMO_MODES
        assert "; rm -rf /" not in ALLOWED_DEMO_MODES

    def test_demo_command_rejects_unknown_mode(self):
        status, output = _demo_command("not-a-real-mode")
        assert status == "Error"
        assert "Invalid demo mode" in output

    def test_demo_command_rejects_none(self):
        status, output = _demo_command(None)
        assert status == "Error"
        assert "Invalid demo mode" in output

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command(["python", 1])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_nul_bytes(self):
        status, output = _run_command(["python", "foo\x00bar"])
        assert status == "Error"
        assert "Invalid command arguments" in output
