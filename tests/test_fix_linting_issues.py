"""Security regression tests for developer maintenance scripts."""

from scripts import fix_linting_issues


def test_run_command_uses_argument_list_without_shell(mocker):
    run_mock = mocker.patch("scripts.fix_linting_issues.subprocess.run")

    assert fix_linting_issues.run_command(["python", "--version"], "Check Python") is True

    run_mock.assert_called_once_with(
        ["python", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
