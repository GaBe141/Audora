"""Security tests for GUI command execution allowlisting."""

import sys
from pathlib import Path

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command


class TestGuiCommandAllowlist:
    """GUI subprocess helpers must refuse untrusted binaries and scripts."""

    def test_known_demo_modes_are_allowlisted(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_rejects_untrusted_binary(self):
        status, output = _run_command(["/bin/echo", "hi"])
        assert status == "Error"
        assert "untrusted" in output.lower()

    def test_rejects_non_main_script(self):
        status, output = _run_command([sys.executable, str(Path("/tmp/evil.py"))])
        assert status == "Error"
        assert "untrusted" in output.lower()

    def test_rejects_non_string_args(self):
        status, output = _run_command([sys.executable, str(MAIN_PY), 1])  # type: ignore[list-item]
        assert status == "Error"
        assert output == "Invalid command"
