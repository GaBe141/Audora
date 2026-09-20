"""Security tests for the lint auto-fix helper."""

from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_lint_script_does_not_use_shell():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "run_command(cmd: list[str]" in source


def test_run_command_invokes_argument_list(monkeypatch):
    captured = {}

    def fake_run(cmd, check, capture_output, text):
        captured["cmd"] = cmd
        captured["kwargs"] = {"check": check, "capture_output": capture_output, "text": text}

        class Result:
            stderr = ""

        return Result()

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)
    assert run_command(["python", "-m", "black", "core/"], "format") is True
    assert captured["cmd"] == ["python", "-m", "black", "core/"]
    assert "shell" not in captured["kwargs"]
