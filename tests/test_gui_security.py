"""Security tests for GUI subprocess and webhook input handling."""

import sys

from gui.app import ALLOWED_DEMO_MODES, _is_safe_argv, _run_command


def test_demo_modes_are_allowlisted():
    assert frozenset({"statistical", "trending", "multi_source", "platform", "all"}) == (
        ALLOWED_DEMO_MODES
    )
    assert "../evil" not in ALLOWED_DEMO_MODES
    assert "statistical; rm -rf /" not in ALLOWED_DEMO_MODES


def test_safe_argv_rejects_non_strings_and_nuls():
    assert _is_safe_argv([sys.executable, "main.py"]) is True
    assert _is_safe_argv(["python", 1]) is False
    assert _is_safe_argv(["python", "foo\x00bar"]) is False
    assert _is_safe_argv([]) is False
    assert _is_safe_argv("python main.py") is False


def test_run_command_rejects_malformed_args_without_spawning():
    status, output = _run_command(["python", "ok\x00evil"])
    assert status == "Error"
    assert output == "Invalid command arguments"
