"""Regression tests for the maintenance lint-fixer script."""

from scripts.fix_linting_issues import run_command


def test_run_command_invokes_subprocess_without_shell(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)
    command = ["python", "-m", "ruff", "check", "file; rm -rf /", "--fix"]

    assert run_command(command, "test command") is True
    assert calls == [
        (
            command,
            {
                "check": True,
                "capture_output": True,
                "text": True,
            },
        )
    ]
