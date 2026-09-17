"""Security tests for the lint auto-fix maintenance script."""

import sys

from scripts.fix_linting_issues import run_command


def test_run_command_rejects_string_payload():
    assert run_command("python -m ruff", "should fail") is False  # type: ignore[arg-type]


def test_run_command_invokes_subprocess_without_shell(monkeypatch):
    captured = {}

    def fake_run(cmd, check=False, capture_output=False, text=False, shell=False):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["check"] = check

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)
    assert run_command([sys.executable, "-c", "print(1)"], "safe") is True
    assert captured["shell"] is False
    assert captured["cmd"] == [sys.executable, "-c", "print(1)"]


def test_source_does_not_enable_shell():
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py").read_text()
    assert "shell=True" not in source
