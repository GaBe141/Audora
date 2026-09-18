"""Security tests for GUI subprocess allowlisting."""

import sys

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command


class TestGuiCommandAllowlist:
    """GUI must not execute client-controlled interpreters or demo values."""

    def test_demo_modes_match_main_cli_choices(self):
        assert frozenset(
            {"statistical", "trending", "multi_source", "platform", "all"}
        ) == ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_main_targets(self):
        status, output = _run_command([sys.executable, "/tmp/evil.py"])
        assert status == "Error"
        assert "Invalid" in output

    def test_run_command_rejects_wrong_interpreter(self):
        status, output = _run_command(["/bin/sh", str(MAIN_PY)])
        assert status == "Error"
        assert "Invalid" in output

    def test_run_command_rejects_malformed_payloads(self):
        status, output = _run_command("python main.py --demo all")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid" in output
