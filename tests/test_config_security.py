"""Security tests for environment loading."""

from unittest.mock import patch

from core.config import SecureConfig


def test_dotenv_does_not_override_process_environment(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SPOTIFY_CLIENT_ID=from_file\n", encoding="utf-8")
    with patch("core.config.load_dotenv") as load_dotenv:
        SecureConfig(env_file=env_file)
    assert load_dotenv.call_args.kwargs["override"] is False
