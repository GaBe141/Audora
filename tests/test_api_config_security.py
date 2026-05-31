"""Security tests for social API credential configuration files."""

import os
from pathlib import Path

from integrations.api_config import SocialAPIManager


def test_default_social_api_config_uses_ignored_secret_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    manager = SocialAPIManager()

    assert manager.config_file == Path("config/social_api_config.json")
    assert manager.config_file.name.endswith("_config.json")
    assert manager.config_file.exists()
    if os.name != "nt":
        assert manager.config_file.stat().st_mode & 0o777 == 0o600
