"""
Temporal Listening Analysis
===========================

Analyze listening patterns across different time dimensions:
- Hour of day (morning, afternoon, evening, night)
- Day of week (weekday vs weekend patterns)
- Seasonal trends
- Listening streak tracking

Provides insights into:
- When you listen to different genres/moods
- Peak listening hours
- Work vs. leisure music patterns
- Energy level correlations with time
"""

from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

from core.utils import (
    confine_child_path,
    ensure_datetime_column,
    load_dataframe,
    resolve_within_project,
    save_report,
)


class TemporalAnalyzer:
    """Analyze temporal patterns in music listening behavior."""

    # Time period definitions
    TIME_PERIODS = {
        "early_morning": (5, 8),  # 5 AM - 8 AM
        "morning": (8, 12),  # 8 AM - 12 PM
        "afternoon": (12, 17),  # 12 PM - 5 PM
        "evening": (17, 21),  # 5 PM - 9 PM
        "night": (21, 24),  # 9 PM - 12 AM
        "late_night": (0, 5),  # 12 AM - 5 AM
    }

    def __init__(self, data_dir: str = "data"):
        """Initialize temporal analyzer."""
        self.data_dir = resolve_within_project(data_dir)
        self.listening_history: pd.DataFrame | None = None
        self.temporal_patterns: dict[str, Any] = {}

    def load_listening_history(self, filename: str = "recently_played.csv") -> pd.DataFrame:
        """Load listening history from CSV file using centralized utility."""
        filepath = confine_child_path(self.data_dir, filename)

        # Try to load with utility
        df = load_dataframe(filepath, default_empty=False)

        if df is None or df.empty:
            print(f"⚠️  File not found or empty: {filepath}")
            return self._generate_sample_data()

        # Convert timestamp columns to datetime
        timestamp_cols = ["played_at", "timestamp", "time", "datetime"]
        for col in timestamp_cols:
            if col in df.columns:
                df = ensure_datetime_column(df, col)
                if col != "played_at":
                    df["played_at"] = df[col]
                break

        # If no timestamp found, generate them
        if "played_at" not in df.columns or not pd.api.types.is_datetime64_any_dtype(
            df["played_at"]
        ):
            print("⚠️  No timestamp column found, generating sample timestamps...")
            df = self._add_sample_timestamps(df)

        self.listening_history = df
        print(f"✅ Loaded {len(df)} listening records")
        return df

    def _generate_sample_data(self) -> pd.DataFrame:
        """Generate sample listening data for demonstration."""
        print("📊 Generating sample listening data...")

        num_records = 100
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)

        # Generate random timestamps
        timestamps = [
            start_date
            + timedelta(seconds=np.random.randint(0, int((end_date - start_date).total_seconds())))
            for _ in range(num_records)
        ]

        tracks = [
            "Vampire",
            "Flowers",
            "Anti-Hero",
            "Calm Down",
            "As It Was",
            "Unholy",
            "Heat Waves",
            "Levitating",
            "Blinding Lights",
            "drivers license",
        ] * (num_records // 10)

        artists = [
            "Olivia Rodrigo",
            "Miley Cyrus",
            "Taylor Swift",
            "Rema",
            "Harry Styles",
            "Sam Smith",
            "Glass Animals",
            "Dua Lipa",
            "The Weeknd",
            "Olivia Rodrigo",
        ] * (num_records // 10)

        df = pd.DataFrame(
            {
                "played_at": timestamps[:num_records],
                "track_name": tracks[:num_records],
                "artist_name": artists[:num_records],
            }
        )

        df = df.sort_values("played_at").reset_index(drop=True)
        return df

    def _add_sample_timestamps(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add sample timestamps to existing dataframe."""
        num_records = len(df)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)

        timestamps = [
            start_date
            + timedelta(seconds=np.random.randint(0, int((end_date - start_date).total_seconds())))
            for _ in range(num_records)
        ]

        df["played_at"] = sorted(timestamps)
        return df

    def extract_temporal_features(self) -> pd.DataFrame:
        """Extract temporal features from listening history."""
        if self.listening_history is None or self.listening_history.empty:
            print("⚠️  No listening history loaded")
            return pd.DataFrame()

        df = self.listening_history.copy()

        # Extract time components
        df["hour"] = df["played_at"].dt.hour
        df["day_of_week"] = df["played_at"].dt.dayofweek  # 0=Monday, 6=Sunday
        df["day_name"] = df["played_at"].dt.day_name()
        df["month"] = df["played_at"].dt.month
        df["month_name"] = df["played_at"].dt.month_name()
        df["date"] = df["played_at"].dt.date
        df["week"] = df["played_at"].dt.isocalendar().week
        df["is_weekend"] = df["day_of_week"].isin([5, 6])  # Saturday, Sunday

        # Categorize into time periods
        df["time_period"] = df["hour"].apply(self._categorize_hour)

        # Add time of day category
        df["time_category"] = df["hour"].apply(
            lambda h: (
                "Morning"
                if 6 <= h < 12
                else "Afternoon" if 12 <= h < 17 else "Evening" if 17 <= h < 21 else "Night"
            )
        )

        return df

    def _categorize_hour(self, hour: int) -> str:
        """Categorize hour into time period."""
        for period, (start, end) in self.TIME_PERIODS.items():
            if start <= hour < end:
                return period
        return "unknown"

    def analyze_hourly_patterns(self) -> dict[str, Any]:
        """Analyze listening patterns by hour of day."""
        df = self.extract_temporal_features()

        if df.empty:
            return {}

        hourly_stats = (
            df.groupby("hour")
            .agg({"track_name": "count", "played_at": "count"})
            .rename(columns={"track_name": "play_count"})
        )

        hourly_stats["percentage"] = (hourly_stats["play_count"] / len(df)) * 100

        peak_hour = hourly_stats["play_count"].idxmax()
        peak_count = hourly_stats["play_count"].max()

        # Time period analysis
        period_stats = df.groupby("time_period").size().to_dict()

        analysis = {
            "hourly_distribution": hourly_stats.to_dict(),
            "peak_listening_hour": int(peak_hour),
            "peak_hour_plays": int(peak_count),
            "period_distribution": period_stats,
            "total_hours_analyzed": df["hour"].nunique(),
            "most_active_period": max(period_stats.items(), key=lambda x: x[1])[0],
        }

        return analysis

    def analyze_weekly_patterns(self) -> dict[str, Any]:
        """Analyze listening patterns by day of week."""
        df = self.extract_temporal_features()

        if df.empty:
            return {}

        daily_stats = (
            df.groupby("day_name")
            .agg({"track_name": "count"})
            .rename(columns={"track_name": "play_count"})
        )

        # Reorder days
        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        daily_stats = daily_stats.reindex([d for d in day_order if d in daily_stats.index])

        # Weekday vs Weekend
        weekday_plays = df[~df["is_weekend"]]["track_name"].count()
        weekend_plays = df[df["is_weekend"]]["track_name"].count()

        analysis = {
            "daily_distribution": daily_stats.to_dict(),
            "weekday_plays": int(weekday_plays),
            "weekend_plays": int(weekend_plays),
            "weekday_avg": float(weekday_plays / 5) if weekday_plays > 0 else 0,
            "weekend_avg": float(weekend_plays / 2) if weekend_plays > 0 else 0,
            "most_active_day": (
                daily_stats["play_count"].idxmax() if not daily_stats.empty else None
            ),
        }

        return analysis

    def analyze_genre_time_patterns(self) -> dict[str, Any]:
        """Analyze which genres/artists are played at different times."""
        df = self.extract_temporal_features()

        if df.empty or "artist_name" not in df.columns:
            return {}

        # Artist preferences by time period
        artist_time = df.groupby(["time_category", "artist_name"]).size().reset_index(name="count")

        # Find top artists for each time period
        top_by_time = {}
        for time_cat in artist_time["time_category"].unique():
            time_data = artist_time[artist_time["time_category"] == time_cat]
            top_artists = time_data.nlargest(5, "count")[["artist_name", "count"]].to_dict(
                "records"
            )
            top_by_time[time_cat] = top_artists

        # Weekend vs Weekday preferences
        weekend_artists = df[df["is_weekend"]].groupby("artist_name").size().nlargest(5)
        weekday_artists = df[~df["is_weekend"]].groupby("artist_name").size().nlargest(5)

        analysis = {
            "by_time_of_day": top_by_time,
            "weekend_favorites": weekend_artists.to_dict(),
            "weekday_favorites": weekday_artists.to_dict(),
        }

        return analysis

    def analyze_listening_streaks(self) -> dict[str, Any]:
        """Analyze consecutive listening days and patterns."""
        df = self.extract_temporal_features()

        if df.empty:
            return {}

        # Get unique listening days (filter out NaT values)
        listening_days = df["date"].dropna().unique()
        listening_days = sorted([d for d in listening_days if pd.notna(d)])

        if not listening_days:
            return {}

        # Calculate streaks
        streaks = []
        current_streak = 1

        for i in range(1, len(listening_days)):
            prev_day = listening_days[i - 1]
            curr_day = listening_days[i]

            # Check if consecutive
            if (curr_day - prev_day).days == 1:
                current_streak += 1
            else:
                if current_streak > 1:
                    streaks.append(current_streak)
                current_streak = 1

        if current_streak > 1:
            streaks.append(current_streak)

        # Current streak from most recent day
        if listening_days:
            last_day = listening_days[-1]
            days_since = (datetime.now().date() - last_day).days

            if days_since == 0:
                # Count backwards from today
                current_streak_days = 1
                for i in range(len(listening_days) - 2, -1, -1):
                    if (listening_days[i + 1] - listening_days[i]).days == 1:
                        current_streak_days += 1
                    else:
                        break
            else:
                current_streak_days = 0
        else:
            current_streak_days = 0

        analysis = {
            "current_streak": current_streak_days,
            "longest_streak": max(streaks) if streaks else 0,
            "total_streaks": len(streaks),
            "avg_streak_length": np.mean(streaks) if streaks else 0,
            "total_listening_days": len(listening_days),
            "days_since_last_listen": days_since if listening_days else None,
        }

        return analysis

    def generate_comprehensive_report(self) -> dict[str, Any]:
        """Generate comprehensive temporal analysis report."""
        print("\n⏰ Analyzing temporal listening patterns...")

        hourly = self.analyze_hourly_patterns()
        weekly = self.analyze_weekly_patterns()
        genre_time = self.analyze_genre_time_patterns()
        streaks = self.analyze_listening_streaks()

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "data_range": {
                "start": (
                    self.listening_history["played_at"].min().isoformat()
                    if not self.listening_history.empty
                    else None
                ),
                "end": (
                    self.listening_history["played_at"].max().isoformat()
                    if not self.listening_history.empty
                    else None
                ),
                "total_records": (
                    len(self.listening_history) if self.listening_history is not None else 0
                ),
            },
            "hourly_patterns": hourly,
            "weekly_patterns": weekly,
            "genre_time_patterns": genre_time,
            "listening_streaks": streaks,
        }

        return report

    def print_insights(self, report: dict[str, Any] | None = None):
        """Print human-readable insights from analysis."""
        if report is None:
            report = self.generate_comprehensive_report()

        print("\n" + "=" * 60)
        print("⏰ TEMPORAL LISTENING ANALYSIS")
        print("=" * 60)

        # Data range
        if report["data_range"]["start"]:
            print("\n📅 Analysis Period:")
            start = datetime.fromisoformat(report["data_range"]["start"])
            end = datetime.fromisoformat(report["data_range"]["end"])
            print(f"   From: {start.strftime('%Y-%m-%d %H:%M')}")
            print(f"   To:   {end.strftime('%Y-%m-%d %H:%M')}")
            print(f"   Total plays: {report['data_range']['total_records']:,}")

        # Hourly patterns
        if report["hourly_patterns"]:
            hourly = report["hourly_patterns"]
            print("\n🕐 Peak Listening Hours:")
            print(
                f"   Most active: {hourly['peak_listening_hour']}:00 ({hourly['peak_hour_plays']} plays)"
            )
            print(
                f"   Most active period: {hourly['most_active_period'].replace('_', ' ').title()}"
            )

            print("\n   Time Period Distribution:")
            for period, count in sorted(
                hourly["period_distribution"].items(), key=lambda x: x[1], reverse=True
            ):
                percentage = (count / report["data_range"]["total_records"]) * 100
                bar = "█" * int(percentage / 2)
                print(
                    f"   {period.replace('_', ' ').title():<15} {bar:<25} {count:>3} plays ({percentage:>5.1f}%)"
                )

        # Weekly patterns
        if report["weekly_patterns"]:
            weekly = report["weekly_patterns"]
            print("\n📆 Weekly Patterns:")
            if weekly["most_active_day"]:
                print(f"   Most active day: {weekly['most_active_day']}")
            print(
                f"   Weekday plays: {weekly['weekday_plays']} (avg {weekly['weekday_avg']:.1f}/day)"
            )
            print(
                f"   Weekend plays: {weekly['weekend_plays']} (avg {weekly['weekend_avg']:.1f}/day)"
            )

        # Genre/Artist time patterns
        if report["genre_time_patterns"] and report["genre_time_patterns"].get("by_time_of_day"):
            print("\n🎵 Music Preferences by Time:")
            for time_cat, artists in report["genre_time_patterns"]["by_time_of_day"].items():
                if artists:
                    print(f"\n   {time_cat}:")
                    for artist_data in artists[:3]:
                        print(
                            f"      • {artist_data['artist_name']} ({artist_data['count']} plays)"
                        )

        # Streaks
        if report["listening_streaks"]:
            streaks = report["listening_streaks"]
            print("\n🔥 Listening Streaks:")
            print(f"   Current streak: {streaks['current_streak']} days")
            print(f"   Longest streak: {streaks['longest_streak']} days")
            print(f"   Total listening days: {streaks['total_listening_days']}")
            if streaks["days_since_last_listen"] is not None:
                print(f"   Days since last listen: {streaks['days_since_last_listen']}")

    def export_report(self, output_file: str | None = None) -> str:
        """Export temporal analysis report to JSON using centralized utility."""
        report = self.generate_comprehensive_report()

        # Use save_report utility
        saved_path = save_report(
            report,
            filename=output_file,
            prefix="temporal_analysis",
            output_dir=str(self.data_dir / "reports"),
            add_timestamp=False,  # Already added in generate_comprehensive_report
        )

        print(f"\n✅ Report exported: {saved_path}")
        return str(saved_path)


def main():
    """Demo of temporal listening analysis."""
    print("⏰ AUDORA TEMPORAL LISTENING ANALYSIS")
    print("=" * 60)

    # Initialize analyzer
    analyzer = TemporalAnalyzer()

    # Load listening history
    analyzer.load_listening_history()

    # Generate and print insights
    report = analyzer.generate_comprehensive_report()
    analyzer.print_insights(report)

    # Export report
    analyzer.export_report()

    print("\n✨ Temporal analysis complete!")


if __name__ == "__main__":
    main()
