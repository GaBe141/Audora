"""Security tests for GUI subprocess allowlisting."""

import sys
from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _is_allowed_command, _run_command, run_action


def test_allowed_demo_modes_match_cli():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_main_payload():
    status, output = _run_command(["/bin/echo", "pwned"])
    assert status == "Error"
    assert "Rejected command" in output


def test_run_command_rejects_non_string_args():
    status, output = _run_command([123, "main.py"])  # type: ignore[list-item]
    assert status == "Error"
    assert "Rejected command" in output


def test_is_allowed_command_requires_current_interpreter(tmp_path):
    main_py = tmp_path / "main.py"
    main_py.write_text("# fake\n", encoding="utf-8")
    assert _is_allowed_command(["python", str(main_py)]) is False


def test_run_action_rejects_unknown_demo_mode():
    with patch("gui.app.ctx") as mock_ctx:
        mock_ctx.triggered_id = "btn-demo"
        status, output = run_action(1, 1, None, None, "; rm -rf /")
    assert status == "Error"
    assert "Rejected demo mode" in output


def test_run_command_allows_project_main():
    with patch("gui.app.subprocess.Popen") as popen:
        proc = popen.return_value
        proc.communicate.return_value = ("ok", None)
        proc.returncode = 0
        status, output = _run_command([sys.executable, str(MAIN_PY), "--setup"])
    assert status == "Done (exit 0)"
    assert output == "ok"
    popen.assert_called_once()
