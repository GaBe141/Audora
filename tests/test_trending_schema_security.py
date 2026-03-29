"""Security tests for trending snapshot export path handling."""

import pytest

from integrations.trending_schema import TrendingSchema


def test_export_trending_snapshot_rejects_absolute_path():
    schema = TrendingSchema()
    with pytest.raises(ValueError, match="not allowed"):
        schema.export_trending_snapshot("/tmp/snapshot.json")


def test_export_trending_snapshot_rejects_parent_traversal():
    schema = TrendingSchema()
    with pytest.raises(ValueError, match="cannot traverse"):
        schema.export_trending_snapshot("../snapshot.json")
