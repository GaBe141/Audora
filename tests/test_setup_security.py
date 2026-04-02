"""Security tests for setup file permission hardening."""

from unittest.mock import patch

from scripts.setup import EnhancedMusicDiscoverySetup


class TestSetupSecurityPermissions:
    """Validate setup writes secret-bearing files with restrictive perms."""

    def test_set_restrictive_permissions_chmods_non_windows(self, tmp_path):
        setup = EnhancedMusicDiscoverySetup()
        target = tmp_path / "secret.json"
        target.write_text("{}", encoding="utf-8")

        with patch("platform.system", return_value="Linux"):
            setup._set_restrictive_permissions(target)

        assert oct(target.stat().st_mode & 0o777) == "0o600"

    def test_set_restrictive_permissions_noop_on_windows(self, tmp_path):
        setup = EnhancedMusicDiscoverySetup()
        target = tmp_path / "secret.json"
        target.write_text("{}", encoding="utf-8")

        initial_mode = target.stat().st_mode & 0o777
        with patch("platform.system", return_value="Windows"):
            setup._set_restrictive_permissions(target)

        assert (target.stat().st_mode & 0o777) == initial_mode
