"""Tests for safe report output path handling."""

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import build_safe_output_path, save_report
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_build_safe_output_path_allows_nested_relative_paths(tmp_path):
    output_path = build_safe_output_path(tmp_path, "nested/report.json")

    assert output_path == tmp_path.resolve() / "nested" / "report.json"


def test_build_safe_output_path_allows_paths_already_under_output_dir(tmp_path):
    output_path = build_safe_output_path(tmp_path, tmp_path / "nested" / "report.json")

    assert output_path == tmp_path.resolve() / "nested" / "report.json"


@pytest.mark.parametrize(
    "filename",
    [
        "../escape.json",
        "nested/../../escape.json",
        "/tmp/escape.json",
    ],
)
def test_build_safe_output_path_rejects_traversal_and_absolute_paths(tmp_path, filename):
    with pytest.raises(ValueError, match="Unsafe output filename"):
        build_safe_output_path(tmp_path, filename)


def test_save_report_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="Unsafe output filename"):
        save_report({"safe": True}, filename="../escape.json", output_dir=str(tmp_path))

    assert not (tmp_path.parent / "escape.json").exists()


def test_save_discovery_report_rejects_path_traversal_without_initializing_app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

    with pytest.raises(ValueError, match="Unsafe output filename"):
        app.save_discovery_report({"safe": True}, custom_filename="../escape.json")

    assert not (tmp_path / "escape.json").exists()


def test_social_discovery_report_rejects_path_traversal_without_initializing_engine(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine.__new__(SocialMusicDiscoveryEngine)

    with pytest.raises(ValueError, match="Unsafe output filename"):
        engine.save_discovery_report({"safe": True}, filepath="../escape.json")

    assert not (tmp_path / "escape.json").exists()
