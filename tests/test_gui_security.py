"""Security tests for GUI command execution guards."""

import pytest

pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("python main.py --demo statistical")  # type: ignore[arg-type]
    assert status == "Error"
    assert output == "Invalid command arguments"


def test_run_command_rejects_non_string_args():
    status, output = _run_command([42, "--demo"])  # type: ignore[list-item]
    assert status == "Error"
    assert output == "Invalid command arguments"


def test_allowed_demo_modes_match_cli_choices():
    assert ALLOWED_DEMO_MODES == frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    )
