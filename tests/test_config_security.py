"""Security tests for environment loading."""

import os

from core.config import SecureConfig


def test_dotenv_does_not_override_process_environment(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("AUDORA_TEST_DOTENV=from-file\n", encoding="utf-8")
    env_file.chmod(0o600)
    monkeypatch.setenv("AUDORA_TEST_DOTENV", "from-process")
    SecureConfig(env_file=str(env_file))
    assert os.environ["AUDORA_TEST_DOTENV"] == "from-process"
