"""Security tests for GUI subprocess orchestration."""

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("python -c 'print(1)'")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_non_string_arguments():
    status, output = _run_command([42, "--demo", "statistical"])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_demo_modes_are_strictly_allowlisted():
    assert "statistical" in ALLOWED_DEMO_MODES
    assert "--demo" not in ALLOWED_DEMO_MODES
    assert "; rm -rf /" not in ALLOWED_DEMO_MODES
    assert len(ALLOWED_DEMO_MODES) == 5
