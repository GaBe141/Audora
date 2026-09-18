"""Security tests for GUI subprocess and webhook handling."""

import sys

import pytest

pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, _is_safe_argv, _run_command


def test_demo_modes_match_cli_choices():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command([123])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command([sys.executable, "main.py\x00--demo"])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_is_safe_argv_accepts_normal_args():
    assert _is_safe_argv([sys.executable, "main.py", "--demo", "statistical"]) is True


def test_save_settings_rejects_non_https_webhook():
    gui_app_module = sys.modules["gui.app"]
    status = gui_app_module.save_settings(
        1,
        "http://example.com/slack",
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert status.startswith("Error:")
    assert "HTTPS" in status
