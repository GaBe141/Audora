"""Security tests for GUI command allowlisting and subprocess guards."""

import sys

import pytest

dash = pytest.importorskip("dash")

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command  # noqa: E402


def test_allowed_demo_modes_match_cli_choices():
    assert frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    ) == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("python main.py")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command payload" in output


def test_run_command_rejects_wrong_interpreter():
    status, output = _run_command(["python", str(MAIN_PY), "--demo", "statistical"])
    assert status == "Error"
    assert "current Python interpreter" in output


def test_run_command_rejects_non_main_script(tmp_path):
    decoy = tmp_path / "evil.py"
    decoy.write_text("print('nope')\n")
    status, output = _run_command([sys.executable, str(decoy)])
    assert status == "Error"
    assert "main.py" in output
