"""Security hardening tests for path safety and cache serialization."""

from pathlib import Path

import pytest

from core.utils import DEFAULT_DATA_DIR, resolve_data_output_path
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


class TestPathSafety:
    """Ensure report writers cannot escape the data directory."""

    def test_resolve_data_output_path_rejects_parent_traversal(self):
        with pytest.raises(ValueError, match="outside data directory"):
            resolve_data_output_path("../secrets.json")

    def test_resolve_data_output_path_accepts_relative_safe_path(self):
        result = resolve_data_output_path("reports/demo.json")
        assert result.is_absolute()
        assert result.is_relative_to(DEFAULT_DATA_DIR)

    def test_resolve_data_output_path_rejects_absolute_outside_data_dir(self):
        with pytest.raises(ValueError, match="outside data directory"):
            resolve_data_output_path("/etc/passwd")

    def test_social_engine_rejects_unsafe_filepath(self):
        engine = SocialMusicDiscoveryEngine(config={"mock_mode": "true"})
        with pytest.raises(ValueError, match="outside data directory"):
            engine.save_discovery_report({"ok": True}, filepath="../../etc/passwd")

    def test_social_engine_writes_under_data_dir(self):
        engine = SocialMusicDiscoveryEngine(config={"mock_mode": "true"})
        output = Path(engine.save_discovery_report({"ok": True}, filepath="reports/test.json"))
        assert output.is_relative_to(DEFAULT_DATA_DIR)

