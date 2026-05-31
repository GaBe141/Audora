"""Regression tests for security scanner configuration."""

import tomllib
from pathlib import Path


def test_bandit_does_not_skip_critical_rules():
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    skipped_rules = set(config["tool"]["bandit"].get("skips", []))

    assert "B301" not in skipped_rules
    assert "B403" not in skipped_rules
    assert "B324" not in skipped_rules
    assert "B608" not in skipped_rules
