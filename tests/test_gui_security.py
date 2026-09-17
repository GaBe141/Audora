"""Security tests for GUI subprocess allowlisting."""

import sys
from pathlib import Path

from gui.app import ALLOWED_DEMO_MODES, ALLOWED_MAIN_SCRIPT, _run_command


class TestGuiCommandAllowlist:
    def test_demo_modes_match_main_parser(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_rejects_non_list_payload(self):
        status, output = _run_command("python main.py --demo statistical")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_rejects_non_string_args(self):
        status, output = _run_command([sys.executable, 123])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_rejects_non_main_script(self, tmp_path):
        other = tmp_path / "evil.py"
        other.write_text("print('nope')\n")
        status, output = _run_command([sys.executable, str(other), "--demo", "statistical"])
        assert status == "Error"
        assert "allowlisted" in output

    def test_rejects_wrong_interpreter(self):
        status, output = _run_command(["/bin/sh", str(ALLOWED_MAIN_SCRIPT), "--setup"])
        assert status == "Error"
        assert "allowlisted" in output

    def test_main_script_points_at_repo_main(self):
        assert Path(__file__).resolve().parent.parent / "main.py" == ALLOWED_MAIN_SCRIPT
        assert ALLOWED_MAIN_SCRIPT.name == "main.py"
