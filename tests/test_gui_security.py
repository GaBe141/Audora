"""Security tests for GUI subprocess argument handling."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _validate_command_args


def test_demo_allowlist_matches_cli_choices():
    expected = frozenset({"statistical", "trending", "multi_source", "platform", "all"})
    assert expected == ALLOWED_DEMO_MODES


def test_validate_command_args_accepts_string_list():
    args = ["python", "main.py", "--demo", "statistical"]
    assert _validate_command_args(args) == args


def test_validate_command_args_rejects_non_strings():
    with pytest.raises(ValueError, match="strings without NUL"):
        _validate_command_args(["python", 1])  # type: ignore[list-item]


def test_validate_command_args_rejects_nul_bytes():
    with pytest.raises(ValueError, match="NUL"):
        _validate_command_args(["python", "main.py\x00--demo"])


def test_validate_command_args_rejects_empty_list():
    with pytest.raises(ValueError, match="non-empty"):
        _validate_command_args([])
