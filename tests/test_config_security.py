"""Security tests for configuration environment loading behavior."""

import os
from pathlib import Path

from core.config import SecureConfig


class TestSecureConfigEnvironmentLoading:
    """Ensure local .env cannot override runtime-provided secrets."""

    def test_env_file_does_not_override_existing_environment(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "SPOTIFY_CLIENT_ID=file_client\n"
            "SPOTIFY_CLIENT_SECRET=file_secret\n"
            "SPOTIFY_REDIRECT_URI=http://127.0.0.1:9999/callback\n",
            encoding="utf-8",
        )

        previous = {
            "SPOTIFY_CLIENT_ID": os.environ.get("SPOTIFY_CLIENT_ID"),
            "SPOTIFY_CLIENT_SECRET": os.environ.get("SPOTIFY_CLIENT_SECRET"),
            "SPOTIFY_REDIRECT_URI": os.environ.get("SPOTIFY_REDIRECT_URI"),
        }
        try:
            os.environ["SPOTIFY_CLIENT_ID"] = "runtime_client"
            os.environ["SPOTIFY_CLIENT_SECRET"] = "runtime_secret"
            os.environ["SPOTIFY_REDIRECT_URI"] = "http://127.0.0.1:8888/callback"

            config = SecureConfig(env_file=str(env_file))
            spotify = config.get_spotify_config()

            assert spotify["client_id"] == "runtime_client"
            assert spotify["client_secret"] == "runtime_secret"
            assert spotify["redirect_uri"] == "http://127.0.0.1:8888/callback"
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
