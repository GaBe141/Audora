"""Tests for the security validation script."""


def test_validate_security_imports_real_config_module():
    from scripts import validate_security

    assert validate_security.SecureConfig.__module__ == "core.config"
