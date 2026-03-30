"""Security tests for command execution scripts."""

from scripts.fix_linting_issues import run_command


def test_fix_script_run_command_uses_arg_list_not_shell(monkeypatch):
    """Ensure command execution is argument-based (no shell string execution)."""
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)

    ok = run_command(["python", "-m", "ruff", "--version"], "check ruff")

    assert ok is True
    assert isinstance(captured["cmd"], list)
    kwargs = captured["kwargs"]
    assert kwargs.get("check") is True
    assert kwargs.get("capture_output") is True
    assert kwargs.get("text") is True
    assert "shell" not in kwargs
