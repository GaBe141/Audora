"""Security tests for GUI subprocess orchestration."""

import subprocess

from gui.app import ALLOWED_DEMO_MODES, _run_command


def test_allowed_demo_modes_are_explicit():
    assert frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    ) == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_list_payloads():
    status, output = _run_command("python -c 'print(1)'")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_non_string_args():
    status, output = _run_command(["python", 123])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_executes_argument_list(monkeypatch):
    class _FakeProc:
        returncode = 0

        def communicate(self, timeout=None):
            return ("ok", None)

        def kill(self):
            raise AssertionError("should not kill")

    captured = {}

    def _fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    status, output = _run_command(["python", "-c", "print(1)"])
    assert status.startswith("Done")
    assert output == "ok"
    assert captured["args"] == ["python", "-c", "print(1)"]
    assert captured["kwargs"].get("shell") is not True
