"""Security tests for GUI subprocess and export helpers."""

from gui.app import ALLOWED_DEMO_MODES, MAX_GUI_EXPORT_ROWS, _run_command


def test_demo_modes_match_cli_allowlist():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command(["echo", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["echo", "bad\x00arg"])
    assert status == "Error"
    assert "Invalid" in output


def test_gui_export_row_cap_is_bounded():
    assert MAX_GUI_EXPORT_ROWS <= 10_000
