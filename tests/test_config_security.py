"""Security tests for configuration loading."""

from core.config import SecureConfig


class TestSecureConfigLoading:
    """Validate secrets from trusted environments cannot be downgraded by .env."""

    def test_env_file_does_not_override_existing_environment(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "SPOTIFY_CLIENT_ID=dotenv-client-id\n"
            "SPOTIFY_CLIENT_SECRET=dotenv-client-secret\n"
            "SPOTIFY_REDIRECT_URI=http://127.0.0.1:8888/dotenv\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "trusted-client-id")
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "trusted-client-secret")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/trusted")

        config = SecureConfig(env_file=str(env_file))

        assert config.get_spotify_config()["client_id"] == "trusted-client-id"
        assert config.get_spotify_config()["client_secret"] == "trusted-client-secret"
        assert config.get_spotify_config()["redirect_uri"] == "http://127.0.0.1:8888/trusted"
