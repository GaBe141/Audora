"""Security tests for GUI command allowlisting."""

import sys

from gui.app import _ALLOWED_DEMO_MODES, _MAIN_PY, _run_command, _run_demo


class TestGuiCommandAllowlist:
    """GUI subprocess helpers must only run allowlisted main.py invocations."""

    def test_rejects_non_list_payload(self):
        status, output = _run_command("python -c 'print(1)'")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_rejects_non_current_interpreter(self):
        status, output = _run_command(["/bin/echo", str(_MAIN_PY), "--setup"])
        assert status == "Error"
        assert "interpreter" in output

    def test_rejects_non_main_script(self, tmp_path):
        decoy = tmp_path / "evil.py"
        decoy.write_text("print('owned')\n", encoding="utf-8")
        status, output = _run_command([sys.executable, str(decoy)])
        assert status == "Error"
        assert "main.py" in output

    def test_allowed_demo_modes_match_cli(self):
        expected = {"statistical", "trending", "multi_source", "platform", "all"}
        assert expected == _ALLOWED_DEMO_MODES

    def test_run_demo_rejects_unknown_mode(self):
        status, output = _run_demo("rm -rf /")
        assert status == "Error"
        assert "Invalid demo mode" in output

    def test_run_demo_rejects_none(self):
        status, output = _run_demo(None)
        assert status == "Error"
        assert "Invalid demo mode" in output
