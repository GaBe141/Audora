"""Advanced integration of statistical analysis with multi-source streaming data."""

import sys
import warnings
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

# Add src directory to path
sys.path.append(str(Path(__file__).parent / "src"))
sys.path.append(str(Path(__file__).parent.parent / "core"))

from analytics.statistical_analysis import StreamingDataQualityAnalyzer, StreamingForecastingEngine
from visualization.statistical_viz import (
    StatisticalVisualizationEngine,
    visualize_comprehensive_results,
)

warnings.filterwarnings("ignore")


class AdvancedStreamingAnalytics:
    """Advanced analytics combining multi-source data with statistical forecasting."""

    def __init__(self, data_dir: str = "data", verbose: bool = True):
        self.data_dir = Path(data_dir)
        self.verbose = verbose

        # Initialize analyzers
        self.quality_analyzer = StreamingDataQualityAnalyzer(verbose=verbose)
        self.forecasting_engine = StreamingForecastingEngine(verbose=verbose)
        self.viz_engine = StatisticalVisualizationEngine()

        # Data containers
        self.raw_data: dict[str, pd.DataFrame] = {}
        self.processed_data: dict[str, pd.DataFrame] = {}
        self.analysis_results: dict[str, Any] = {}
        self.forecasts: dict[str, Any] = {}

        if verbose:
            print("🚀 Advanced Streaming Analytics initialized")
            print(f"   Data directory: {self.data_dir}")

    def load_multi_source_data(self) -> dict[str, pd.DataFrame]:
        """Load data from multiple sources."""
        print("\n📂 Loading multi-source streaming data...")

        data_files = {
            "spotify_basic": "simple_top_tracks.csv",
            "spotify_artists": "simple_top_artists.csv",
            "lastfm_tracks": "lastfm_global_tracks.csv",
            "lastfm_artists": "lastfm_global_artists.csv",
            "musicbrainz": "musicbrainz_enriched.csv",
            "audiodb": "audiodb_enriched.csv",
            "recently_played": "recently_played.csv",
        }

        loaded_data = {}

        for source, filename in data_files.items():
            file_path = self.data_dir / filename
            if file_path.exists():
                try:
                    df = pd.read_csv(file_path)
                    loaded_data[source] = df
                    if self.verbose:
                        print(f"   ✅ {source}: {len(df)} rows, {len(df.columns)} columns")
                except Exception as e:
                    if self.verbose:
                        print(f"   ❌ {source}: Error loading - {e}")
            else:
                if self.verbose:
                    print(f"   ⚠️ {source}: File not found - {filename}")

        self.raw_data = loaded_data
        return loaded_data

    def prepare_time_series_data(self) -> dict[str, pd.DataFrame]:
        """Prepare time series data for analysis."""
        print("\n🔧 Preparing time series data...")

        time_series_data = {}

        # Process recently played data for time series analysis
        if "recently_played" in self.raw_data:
            df = self.raw_data["recently_played"].copy()

            if "played_at" in df.columns:
                try:
                    # Convert to datetime
                    df["played_at"] = pd.to_datetime(df["played_at"])
                    df = df.sort_values("played_at")

                    # Create daily aggregations
                    df["date"] = df["played_at"].dt.date
                    daily_stats = (
                        df.groupby("date")
                        .agg(
                            {
                                "track_name": "count",  # plays per day
                                "artist_name": "nunique",  # unique artists per day
                                "duration_ms": ["mean", "sum"],  # avg and total duration
                            }
                        )
                        .reset_index()
                    )

                    # Flatten column names
                    daily_stats.columns = [
                        "date",
                        "daily_plays",
                        "unique_artists",
                        "avg_duration",
                        "total_duration",
                    ]
                    daily_stats["date"] = pd.to_datetime(daily_stats["date"])

                    time_series_data["daily_listening"] = daily_stats

                    if self.verbose:
                        print(f"   ✅ Daily listening: {len(daily_stats)} days")
                        print(
                            f"      Date range: {daily_stats['date'].min()} to {daily_stats['date'].max()}"
                        )

                except Exception as e:
                    if self.verbose:
                        print(f"   ❌ Error processing recently played data: {e}")

        # Create synthetic streaming data for demonstration
        if not time_series_data:
            print("   📊 Creating synthetic streaming data for analysis...")
            time_series_data = self._create_synthetic_streaming_data()

        self.processed_data = time_series_data
        return time_series_data

    def _create_synthetic_streaming_data(self) -> dict[str, pd.DataFrame]:
        """Create realistic synthetic streaming data for analysis."""
        # Generate 6 months of data
        start_date = datetime.now() - timedelta(days=180)
        dates = pd.date_range(start_date, periods=180, freq="D")

        # Create realistic patterns
        base_streams = 1000 + np.cumsum(np.random.normal(2, 10, 180))  # Growing trend
        weekly_pattern = np.sin(np.arange(180) * 2 * np.pi / 7) * 200  # Weekly cycle
        monthly_pattern = np.sin(np.arange(180) * 2 * np.pi / 30) * 100  # Monthly cycle
        noise = np.random.normal(0, 50, 180)

        streams = base_streams + weekly_pattern + monthly_pattern + noise
        streams = np.maximum(streams, 100)  # Minimum streams

        # Related metrics
        listeners = streams * np.random.uniform(0.3, 0.6, 180)
        skips = streams * np.random.uniform(0.1, 0.3, 180)
        saves = streams * np.random.uniform(0.05, 0.15, 180)

        # Add some missing values and outliers
        missing_indices = np.random.choice(180, 8, replace=False)
        streams[missing_indices] = np.nan

        viral_indices = np.random.choice(180, 2, replace=False)
        streams[viral_indices] *= np.random.uniform(2.5, 4.0, 2)

        synthetic_data = pd.DataFrame(
            {
                "date": dates,
                "daily_plays": streams,
                "unique_artists": listeners / 50,  # Rough estimate
                "avg_duration": np.random.normal(180000, 30000, 180),  # ~3 min average
                "total_duration": streams * np.random.normal(180000, 30000, 180),
                "skips": skips,
                "saves": saves,
            }
        )

        return {"daily_listening": synthetic_data}

    def run_quality_analysis(self) -> dict[str, Any]:
        """Run comprehensive data quality analysis."""
        print("\n🔍 Running data quality analysis...")

        quality_results = {}

        for source, df in self.processed_data.items():
            print(f"\n   Analyzing {source}...")

            # Determine timestamp and value columns
            timestamp_col = "date" if "date" in df.columns else df.columns[0]
            value_cols = [
                col
                for col in df.columns
                if col != timestamp_col and df[col].dtype in ["int64", "float64"]
            ]

            if not value_cols:
                print(f"   ⚠️ No numeric columns found in {source}")
                continue

            try:
                quality_report = self.quality_analyzer.analyze_data_quality(
                    data=df, timestamp_col=timestamp_col, value_cols=value_cols
                )

                quality_results[source] = quality_report

                # Print summary
                missing_count = sum(quality_report["basic_stats"]["missing_values"].values())
                rec_count = len(quality_report.get("recommendations", []))

                print("   ✅ Quality analysis complete")
                print(f"      Missing values: {missing_count}")
                print(f"      Recommendations: {rec_count}")

            except Exception as e:
                print(f"   ❌ Quality analysis failed: {e}")
                quality_results[source] = {"error": str(e)}

        return quality_results

    def run_forecasting_analysis(self) -> dict[str, Any]:
        """Run comprehensive forecasting analysis."""
        print("\n📈 Running forecasting analysis...")

        forecasting_results = {}

        for source, df in self.processed_data.items():
            print(f"\n   Forecasting {source}...")

            timestamp_col = "date" if "date" in df.columns else df.columns[0]
            value_cols = [
                col
                for col in df.columns
                if col != timestamp_col and df[col].dtype in ["int64", "float64"]
            ]

            source_results = {}

            for col in value_cols[:3]:  # Limit to first 3 columns for performance
                try:
                    print(f"      Analyzing {col}...")

                    # Prepare time series
                    ts, prep_info = self.forecasting_engine.prepare_time_series(
                        df, timestamp_col, col
                    )

                    if len(ts) < 20:
                        print(f"      ⚠️ Insufficient data for {col}")
                        continue

                    col_results = {"preparation": prep_info, "models": {}, "forecasts": {}}

                    # Fit models
                    print("         Fitting models...")

                    # ARIMA
                    if self.forecasting_engine.available_models["arima"]:
                        arima_result = self.forecasting_engine.fit_arima_model(ts)
                        col_results["models"]["arima"] = arima_result

                    # SARIMA
                    if self.forecasting_engine.available_models["sarima"]:
                        sarima_result = self.forecasting_engine.fit_sarima_model(ts)
                        col_results["models"]["sarima"] = sarima_result

                    # Darts models (with error handling)
                    if self.forecasting_engine.available_models["auto_arima"]:
                        try:
                            darts_results = self.forecasting_engine.fit_darts_models(ts)
                            col_results["models"]["darts"] = darts_results
                        except Exception as e:
                            print(f"         ⚠️ Darts models failed: {e}")

                    # Generate forecasts
                    print("         Generating forecasts...")
                    forecasts = self.forecasting_engine.generate_forecasts(ts, horizon=14)
                    col_results["forecasts"] = forecasts

                    # Evaluate performance
                    try:
                        performance = self.forecasting_engine.evaluate_model_performance(ts)
                        col_results["performance"] = performance
                    except Exception as e:
                        print(f"         ⚠️ Performance evaluation failed: {e}")

                    source_results[col] = col_results

                    # Print summary
                    model_count = len(
                        [
                            m
                            for m in col_results["models"].values()
                            if isinstance(m, dict) and m.get("success", False)
                        ]
                    )
                    forecast_count = len(
                        [f for f in col_results["forecasts"].values() if "forecast" in f]
                    )

                    print(f"         ✅ {model_count} models, {forecast_count} forecasts")

                except Exception as e:
                    print(f"      ❌ Forecasting failed for {col}: {e}")
                    source_results[col] = {"error": str(e)}

            if source_results:
                forecasting_results[source] = source_results

        self.forecasts = forecasting_results
        return forecasting_results

    def generate_insights(self) -> dict[str, Any]:
        """Generate actionable insights from analysis results."""
        print("\n💡 Generating actionable insights...")

        insights = {
            "data_quality_insights": [],
            "forecasting_insights": [],
            "anomaly_insights": [],
            "recommendation_summary": [],
            "key_metrics": {},
        }

        # Data quality insights
        for source, quality_data in self.analysis_results.get("quality", {}).items():
            if "error" in quality_data:
                continue

            # Missing data insights
            missing_data = quality_data.get("basic_stats", {}).get("missing_values", {})
            if missing_data:
                total_missing = sum(missing_data.values())
                total_rows = quality_data.get("basic_stats", {}).get("total_rows", 1)
                missing_pct = (total_missing / total_rows) * 100

                if missing_pct > 10:
                    insights["data_quality_insights"].append(
                        f"HIGH MISSING DATA ALERT: {source} has {missing_pct:.1f}% missing values"
                    )
                elif missing_pct > 5:
                    insights["data_quality_insights"].append(
                        f"Moderate missing data in {source}: {missing_pct:.1f}%"
                    )

            # Outlier insights
            outlier_data = quality_data.get("outlier_analysis", {})
            for col, outliers in outlier_data.items():
                if "iqr" in outliers and outliers["iqr"]["percentage"] > 15:
                    insights["anomaly_insights"].append(
                        f"ANOMALY DETECTED: {col} in {source} has {outliers['iqr']['percentage']:.1f}% outliers"
                    )

        # Forecasting insights
        for _source, source_data in self.forecasts.items():
            for col, col_data in source_data.items():
                if "error" in col_data:
                    continue

                # Model performance insights
                performance = col_data.get("performance", {})
                if performance:
                    best_model = None
                    best_mae = float("inf")

                    for model_name, metrics in performance.items():
                        if (
                            isinstance(metrics, dict)
                            and "mae" in metrics
                            and metrics["mae"] < best_mae
                        ):
                            best_mae = metrics["mae"]
                            best_model = model_name

                    if best_model:
                        insights["forecasting_insights"].append(
                            f"BEST FORECAST MODEL for {col}: {best_model} (MAE: {best_mae:.2f})"
                        )

                # Forecast trend insights
                forecasts = col_data.get("forecasts", {})
                for _model_name, forecast_data in forecasts.items():
                    if "forecast" in forecast_data:
                        forecast_values = forecast_data["forecast"][:7]  # Next week
                        if len(forecast_values) >= 2:
                            trend = (
                                "INCREASING"
                                if forecast_values[-1] > forecast_values[0]
                                else "DECREASING"
                            )
                            change_pct = (
                                (forecast_values[-1] - forecast_values[0]) / forecast_values[0]
                            ) * 100

                            if abs(change_pct) > 10:
                                insights["forecasting_insights"].append(
                                    f"TREND ALERT: {col} predicted to be {trend} by {abs(change_pct):.1f}% next week"
                                )

        # Generate recommendations
        all_recommendations = []
        for _source, quality_data in self.analysis_results.get("quality", {}).items():
            recommendations = quality_data.get("recommendations", [])
            all_recommendations.extend(recommendations)

        # Prioritize recommendations
        high_priority = [
            rec
            for rec in all_recommendations
            if any(word in rec.lower() for word in ["high", "critical", "urgent", "error"])
        ]
        medium_priority = [
            rec
            for rec in all_recommendations
            if any(word in rec.lower() for word in ["moderate", "warning", "consider"])
        ]
        low_priority = [
            rec for rec in all_recommendations if rec not in high_priority + medium_priority
        ]

        insights["recommendation_summary"] = {
            "high_priority": high_priority,
            "medium_priority": medium_priority,
            "low_priority": low_priority,
        }

        # Key metrics summary
        insights["key_metrics"] = {
            "total_sources_analyzed": len(self.processed_data),
            "total_quality_issues": len(all_recommendations),
            "forecast_models_successful": self._count_successful_models(),
            "anomalies_detected": len(insights["anomaly_insights"]),
        }

        return insights

    def _count_successful_models(self) -> int:
        """Count successful forecasting models across all analyses."""
        count = 0
        for source_data in self.forecasts.values():
            for col_data in source_data.values():
                if "models" in col_data:
                    for model_result in col_data["models"].values():
                        if isinstance(model_result, dict) and model_result.get("success", False):
                            count += 1
        return count

    def create_comprehensive_report(self, output_dir: str = "data/advanced_analysis") -> str:
        """Create comprehensive analysis report with visualizations."""
        print("\n📊 Creating comprehensive analysis report...")

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Combine all results
        comprehensive_results = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "advanced_multi_source_streaming_analysis",
            "data_sources": list(self.raw_data.keys()),
            "data_quality": self.analysis_results.get("quality", {}),
            "forecasting": self.forecasts,
            "insights": self.analysis_results.get("insights", {}),
            "summary": {
                "total_sources": len(self.raw_data),
                "processed_datasets": len(self.processed_data),
                "quality_analyses": len(self.analysis_results.get("quality", {})),
                "forecast_analyses": len(self.forecasts),
            },
        }

        # Save results using centralized utility
        from core.utils import write_json

        results_file = output_path / "comprehensive_analysis_results.json"
        write_json(str(results_file), comprehensive_results)

        print(f"   ✅ Results saved to {results_file}")

        # Create visualizations
        try:
            viz_path = visualize_comprehensive_results(
                str(results_file), str(output_path / "visualizations")
            )
            print(f"   ✅ Visualizations created in {viz_path}")
        except Exception as e:
            print(f"   ⚠️ Visualization creation failed: {e}")

        # Create summary report
        summary_file = output_path / "analysis_summary.txt"
        self._create_text_summary(comprehensive_results, summary_file)

        print("\n🎯 Comprehensive analysis complete!")
        print(f"   📁 Report directory: {output_path}")
        print(f"   📄 Main results: {results_file.name}")
        print(f"   📊 Summary: {summary_file.name}")

        return str(output_path)

    def _create_text_summary(self, results: dict[str, Any], output_file: Path):
        """Create human-readable text summary."""
        with output_file.open("w") as f:
            f.write("SPOTIFY INSIGHTS - ADVANCED STATISTICAL ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Generated: {results['timestamp']}\n")
            f.write(f"Analysis Type: {results['analysis_type']}\n\n")

            # Summary section
            summary = results.get("summary", {})
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Data Sources Analyzed: {summary.get('total_sources', 0)}\n")
            f.write(f"Datasets Processed: {summary.get('processed_datasets', 0)}\n")
            f.write(f"Quality Analyses: {summary.get('quality_analyses', 0)}\n")
            f.write(f"Forecast Analyses: {summary.get('forecast_analyses', 0)}\n\n")

            # Insights section
            insights = results.get("insights", {})
            if insights:
                f.write("KEY INSIGHTS\n")
                f.write("-" * 15 + "\n")

                for insight_type, insight_list in insights.items():
                    if isinstance(insight_list, list) and insight_list:
                        f.write(f"\n{insight_type.upper().replace('_', ' ')}:\n")
                        for insight in insight_list:
                            f.write(f"  • {insight}\n")

            f.write(
                "\nFor detailed results and visualizations, see the JSON file and visualization folder.\n"
            )

    def run_complete_analysis(self) -> str:
        """Run the complete advanced analytics pipeline."""
        print("🚀 STARTING ADVANCED STREAMING ANALYTICS PIPELINE")
        print("=" * 60)

        try:
            # Step 1: Load data
            self.load_multi_source_data()

            # Step 2: Prepare time series
            self.prepare_time_series_data()

            # Step 3: Quality analysis
            quality_results = self.run_quality_analysis()

            # Step 4: Forecasting analysis
            forecasting_results = self.run_forecasting_analysis()

            # Step 5: Generate insights
            insights = self.generate_insights()

            # Store results
            self.analysis_results = {
                "quality": quality_results,
                "forecasting": forecasting_results,
                "insights": insights,
            }

            # Step 6: Create comprehensive report
            report_path = self.create_comprehensive_report()

            print("\n🎉 ADVANCED ANALYTICS PIPELINE COMPLETED SUCCESSFULLY!")
            return report_path

        except Exception as e:
            print(f"\n❌ Pipeline failed: {e}")
            import traceback

            traceback.print_exc()
            return ""


if __name__ == "__main__":
    print("🎵 Spotify Insights - Advanced Streaming Analytics")
    print("=" * 60)

    # Initialize and run advanced analytics
    analytics = AdvancedStreamingAnalytics(verbose=True)

    # Run complete analysis
    report_path = analytics.run_complete_analysis()

    if report_path:
        print(f"\n✅ Analysis complete! Check results in: {report_path}")
    else:
        print("\n❌ Analysis failed. Check error messages above.")
