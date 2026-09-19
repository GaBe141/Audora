"""Security tests for GUI subprocess and webhook handling."""

import pytest

dash = pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, MAX_GUI_EXPORT_ROWS, _run_command  # noqa: E402


def test_allowed_demo_modes_match_cli_choices():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command([123, "main.py"])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["python", "main.py\x00--demo"])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_empty_payload():
    status, output = _run_command([])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_gui_export_row_cap_is_bounded():
    assert MAX_GUI_EXPORT_ROWS == 100_000
