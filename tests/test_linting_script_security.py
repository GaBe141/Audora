"""Security tests for the maintenance linting script."""

import inspect

from scripts.fix_linting_issues import run_command


def test_run_command_does_not_use_shell(monkeypatch):
    captured: dict = {}

    def _fake_run(cmd, check=False, capture_output=False, text=False, shell=False):
        captured["cmd"] = cmd
        captured["shell"] = shell

        class _Result:
            stderr = ""

        return _Result()

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", _fake_run)
    assert run_command(["python", "-m", "ruff", "check"], "lint") is True
    assert captured["cmd"] == ["python", "-m", "ruff", "check"]
    assert captured["shell"] is False


def test_script_source_has_no_shell_true():
    source = inspect.getsource(run_command)
    assert "shell=True" not in source
