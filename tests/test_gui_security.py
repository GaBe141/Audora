"""Security tests for GUI subprocess orchestration."""

import pytest

pytest.importorskip("dash")

from gui.app import _ALLOWED_DEMO_MODES, _run_command  # noqa: E402


class TestGuiCommandHardening:
    """GUI must not pass unsanitized values into subprocesses."""

    def test_demo_allowlist_matches_main_parser(self):
        assert frozenset(
            {"statistical", "trending", "multi_source", "platform", "all"}
        ) == _ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command(["python", 1])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_empty_args(self):
        status, output = _run_command([])
        assert status == "Error"
        assert "Invalid command arguments" in output
