"""Security tests for the linting maintenance script."""

from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_linting_script_does_not_use_shell():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source


def test_run_command_uses_argument_list_and_rejects_missing_binary():
    assert run_command(["python-not-a-real-binary-xyz", "--help"], "missing binary") is False


def test_run_command_reports_nonzero_exit():
    assert (
        run_command(
            [__import__("sys").executable, "-c", "raise SystemExit(1)"],
            "nonzero exit",
        )
        is False
    )
