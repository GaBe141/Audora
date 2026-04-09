"""Security regression tests for script command execution."""

import scripts.fix_linting_issues as fix_script


def test_run_command_uses_no_shell(monkeypatch):
    """Ensure automation commands are executed without shell=True."""
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr(fix_script.subprocess, "run", fake_run)
    assert fix_script.run_command(["python", "--version"], "version check")

    assert "kwargs" in captured
    assert captured["kwargs"].get("shell") is None
    assert captured["kwargs"].get("check") is True
    assert captured["kwargs"].get("capture_output") is True
    assert captured["kwargs"].get("text") is True


def test_run_command_splits_string_without_shell(monkeypatch):
    """Ensure string commands are tokenized before subprocess invocation."""
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr(fix_script.subprocess, "run", fake_run)
    assert fix_script.run_command("python -m pip --version", "pip version")

    assert captured["command"] == ["python", "-m", "pip", "--version"]
    assert captured["kwargs"].get("shell") is None
