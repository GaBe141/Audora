"""Security tests for GUI command and webhook handling."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _validate_subprocess_args


def test_demo_allowlist_matches_main_choices():
    expected = {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    }
    assert expected == ALLOWED_DEMO_MODES


def test_validate_subprocess_args_accepts_string_list():
    args = ["python", "main.py", "--demo", "statistical"]
    assert _validate_subprocess_args(args) == args


def test_validate_subprocess_args_rejects_non_list():
    with pytest.raises(ValueError, match="non-empty list"):
        _validate_subprocess_args("python main.py")  # type: ignore[arg-type]


def test_validate_subprocess_args_rejects_non_string_items():
    with pytest.raises(ValueError, match="Invalid command argument"):
        _validate_subprocess_args(["python", 123])  # type: ignore[list-item]


def test_validate_subprocess_args_rejects_nul_bytes():
    with pytest.raises(ValueError, match="Invalid command argument"):
        _validate_subprocess_args(["python", "main.py\x00--setup"])
