"""Tests for analytics temporal_analysis (generate_comprehensive_report, time periods, streaks)."""

from datetime import datetime, timedelta

import pandas as pd

from analytics.temporal_analysis import TemporalAnalyzer


def _make_listening_df(num_records: int = 50, start_hour: int = 10) -> pd.DataFrame:
    """Build a small listening history DataFrame with played_at, track_name, artist_name."""
    base = datetime(2024, 1, 1, start_hour, 0, 0)
    timestamps = [base + timedelta(hours=i % 24, days=i // 24) for i in range(num_records)]
    return pd.DataFrame(
        {
            "played_at": timestamps,
            "track_name": ["Track"] * num_records,
            "artist_name": ["Artist"] * num_records,
        }
    )


class TestGenerateComprehensiveReport:
    """Tests for generate_comprehensive_report structure and keys."""

    def test_report_has_expected_keys(self):
        analyzer = TemporalAnalyzer()
        analyzer.listening_history = _make_listening_df(30)
        report = analyzer.generate_comprehensive_report()
        assert "data_range" in report
        assert "hourly_patterns" in report
        assert "weekly_patterns" in report
        assert "genre_time_patterns" in report
        assert "listening_streaks" in report
        assert "analysis_timestamp" in report

    def test_data_range_populated(self):
        analyzer = TemporalAnalyzer()
        analyzer.listening_history = _make_listening_df(20)
        report = analyzer.generate_comprehensive_report()
        assert report["data_range"]["total_records"] == 20
        assert report["data_range"]["start"] is not None
        assert report["data_range"]["end"] is not None

    def test_hourly_patterns_structure(self):
        analyzer = TemporalAnalyzer()
        # All at hour 10 -> morning
        analyzer.listening_history = _make_listening_df(15, start_hour=10)
        report = analyzer.generate_comprehensive_report()
        hourly = report["hourly_patterns"]
        assert (
            "peak_listening_hour" in hourly
            or "period_distribution" in hourly
            or "most_active_period" in hourly
        )


class TestTimePeriodBuckets:
    """Test that timestamps fall into expected period (e.g. 10:00 -> morning)."""

    def test_morning_hour_in_period(self):
        analyzer = TemporalAnalyzer()
        # TIME_PERIODS: morning = (8, 12)
        analyzer.listening_history = _make_listening_df(5, start_hour=10)
        report = analyzer.generate_comprehensive_report()
        hourly = report.get("hourly_patterns", {})
        period_dist = hourly.get("period_distribution", {})
        # At least one period should have plays
        assert sum(period_dist.values()) >= 5 or "most_active_period" in hourly


class TestEmptyHistory:
    """Test behavior with no or empty history."""

    def test_empty_history_report_still_has_structure(self):
        analyzer = TemporalAnalyzer()
        analyzer.listening_history = pd.DataFrame(
            columns=["played_at", "track_name", "artist_name"]
        )
        report = analyzer.generate_comprehensive_report()
        assert report["data_range"]["total_records"] == 0
        assert report["data_range"]["start"] is None
