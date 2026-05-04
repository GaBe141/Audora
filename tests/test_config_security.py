"""Security-focused tests for configuration loading."""

from core.config import SecureConfig


def test_env_file_does_not_override_existing_environment(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SPOTIFY_CLIENT_ID=file_client_id",
                "SPOTIFY_CLIENT_SECRET=file_client_secret",
                "SPOTIFY_REDIRECT_URI=http://127.0.0.1:9999/callback",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("SPOTIFY_CLIENT_ID", "runtime_client_id")
    monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "runtime_client_secret")
    monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")

    config = SecureConfig(env_file=str(env_file))

    spotify_config = config.get_spotify_config()
    assert spotify_config["client_id"] == "runtime_client_id"
    assert spotify_config["client_secret"] == "runtime_client_secret"
    assert spotify_config["redirect_uri"] == "http://127.0.0.1:8888/callback"
