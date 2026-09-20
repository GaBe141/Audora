"""Security tests for GUI subprocess arguments and demo allowlisting."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _validate_cli_args


def test_demo_allowlist_is_explicit():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == ALLOWED_DEMO_MODES


def test_validate_cli_args_accepts_safe_argv():
    args = ["python", "main.py", "--demo", "statistical"]
    assert _validate_cli_args(args) == args


def test_validate_cli_args_rejects_nul_bytes():
    with pytest.raises(ValueError, match="Invalid command argument"):
        _validate_cli_args(["python", "main.py\x00--demo"])


def test_validate_cli_args_rejects_non_string_values():
    with pytest.raises(ValueError, match="Invalid command argument"):
        _validate_cli_args(["python", 123])  # type: ignore[list-item]
