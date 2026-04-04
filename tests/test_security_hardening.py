"""Security hardening tests for critical flaw regressions."""

import pytest

from core.notification_service import EnhancedNotificationService


class TestNotificationEmailHardening:
    """Ensure email channel rejects common abuse vectors."""

    @pytest.mark.asyncio
    async def test_rejects_header_injection_from_address(self, monkeypatch):
        monkeypatch.setenv("SMTP_SERVER", "smtp.example.com")
        monkeypatch.setenv("EMAIL_RECIPIENTS", "user@example.com")
        monkeypatch.setenv("SMTP_FROM", "ops@example.com\r\nBcc:attacker@example.com")

        svc = EnhancedNotificationService()
        from core.notification_service import NotificationChannel, NotificationMessage, NotificationPriority

        result = await svc._send_email(  # noqa: SLF001 - direct security-path test
            NotificationMessage(
                title="hello",
                content="world",
                priority=NotificationPriority.LOW,
                channels=[NotificationChannel.EMAIL],
            )
        )
        assert result["success"] is False
        assert "from address" in result["error"].lower()

    def test_rejects_attachment_outside_allowed_roots(self, tmp_path):
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret", encoding="utf-8")

        svc = EnhancedNotificationService()
        assert svc._validate_attachment_path(str(outside_file)) is None  # noqa: SLF001


class TestDataStoreCacheKeyHardening:
    """Ensure cache keys are deterministic and stable."""

    def test_bulk_cache_key_deterministic(self):
        from core.data_store import EnhancedMusicDataStore

        pairs = [("Track A", "Artist Z"), ("Track B", "Artist Y")]
        key1 = EnhancedMusicDataStore._build_bulk_track_cache_key(pairs)  # noqa: SLF001
        key2 = EnhancedMusicDataStore._build_bulk_track_cache_key(list(reversed(pairs)))  # noqa: SLF001
        assert key1 == key2
        assert key1.startswith("tracks_bulk:")


class TestNoShellExecution:
    """Ensure lint-fix helper does not use shell=True execution."""

    def test_run_command_uses_argv_list(self):
        from scripts.fix_linting_issues import run_command

        captured: dict[str, object] = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

            class Result:
                returncode = 0

            return Result()

        import subprocess

        original = subprocess.run
        subprocess.run = fake_run
        try:
            assert run_command(["python3", "--version"], "version check") is True
        finally:
            subprocess.run = original

        kwargs = captured["kwargs"]
        assert kwargs.get("shell", False) is False
        assert isinstance(captured["args"][0][0], str)
        assert captured["args"][0][0] == "python3"
