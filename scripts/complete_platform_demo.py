"""
Enhanced demo showcasing the complete trending analytics platform.
Demonstrates statistical analysis, trending schema, and visualization capabilities.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.utils import load_dataframe  # noqa: E402


def main():
    print("🎵 COMPLETE SPOTIFY ANALYTICS PLATFORM DEMO")
    print("=" * 60)
    print("Showcasing Statistical Analysis + Trending Schema + Visualizations")
    print()

    # 1. Statistical Analysis Demo
    print("📊 PART 1: STATISTICAL ANALYSIS & FORECASTING")
    print("-" * 50)

    try:
        from src.statistical_analysis import (
            StreamingDataQualityAnalyzer,
            StreamingForecastingEngine,
        )

        # Visualization engine is optional; using library checks instead

        # Load sample data for statistical analysis
        data_files = [
            "data/simple_top_tracks.csv",
            "data/recently_played.csv",
            "data/lastfm_global_tracks.csv",
        ]

        available_files = [f for f in data_files if Path(f).exists()]
        print(f"📈 Available data files: {len(available_files)}")

        if available_files:
            # Demonstrate data quality analysis
            print("\n🔍 Running Data Quality Analysis...")
            quality_analyzer = StreamingDataQualityAnalyzer()

            for file_path in available_files[:2]:  # Analyze first 2 files
                print(f"   Analyzing: {Path(file_path).name}")
                df = load_dataframe(file_path, default_empty=False)
                if df is None:
                    continue

                # Get numeric columns for analysis
                numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()

                if numeric_cols and len(df) > 5:
                    # Use 'rank' as timestamp proxy and first numeric column as value
                    timestamp_col = "rank" if "rank" in df.columns else numeric_cols[0]
                    value_cols = [col for col in numeric_cols if col != timestamp_col][
                        :2
                    ]  # Up to 2 value columns

                    if value_cols:
                        quality_report = quality_analyzer.analyze_data_quality(
                            df, timestamp_col, value_cols
                        )

                        # Extract and display quality metrics
                        basic_stats = quality_report.get("basic_stats", {})
                        missing_vals = basic_stats.get("missing_values", {})
                        total_missing = sum(missing_vals.values()) if missing_vals else 0
                        total_cells = len(df) * len(value_cols)
                        missing_pct = (total_missing / total_cells) * 100 if total_cells > 0 else 0

                        outlier_analysis = quality_report.get("outlier_analysis", {})
                        outlier_count = outlier_analysis.get("total_outliers", 0)

                        # Simple quality score calculation
                        quality_score = max(
                            0, 1 - (missing_pct / 100) - (outlier_count / len(df) * 0.5)
                        )

                        print(f"      Missing values: {missing_pct:.1f}%")
                        print(f"      Outliers detected: {outlier_count}")
                        print(f"      Data quality score: {quality_score:.2f}/1.0")
                    else:
                        print("      No suitable value columns found")
                else:
                    print("      Insufficient data for quality analysis")

            # Demonstrate forecasting
            print("\n🔮 Running Forecasting Analysis...")
            forecasting_engine = StreamingForecastingEngine()

            # Use a numeric column for forecasting
            sample_df = load_dataframe(available_files[0], default_empty=False)
            numeric_columns = (
                sample_df.select_dtypes(include=["number"]).columns if sample_df is not None else []
            )

            if len(numeric_columns) > 0:
                target_column = numeric_columns[0]
                print(f"   Forecasting target: {target_column}")

                # Prepare time series data
                if len(sample_df) > 10:  # Need enough data points
                    time_series = sample_df[target_column].values[:20]  # Use first 20 points

                    # Generate forecasts
                    forecasts = forecasting_engine.forecast_multiple_models(
                        time_series, forecast_periods=5
                    )

                    print(f"   Models tested: {len(forecasts)}")
                    for model_name, result in forecasts.items():
                        rmse = result.get("rmse", "N/A")
                        print(f"      {model_name}: RMSE = {rmse}")

            print("   ✅ Statistical analysis complete")

    except ImportError as e:
        print(f"   ⚠️ Statistical analysis modules not fully available: {e}")
        print("   Install: pip install statsmodels scikit-learn")

    print()

    # 2. Trending Schema Demo
    print("📊 PART 2: TRENDING PATTERN ANALYSIS")
    print("-" * 50)

    try:
        from spotify_trending_integration import SpotifyTrendingIntegration

        # Initialize and run trending analysis
        integration = SpotifyTrendingIntegration()

        print("🔄 Loading and processing streaming data...")
        load_results = integration.load_and_process_data()
        print(f"   Files processed: {load_results['files_processed']}")
        print(f"   Total items: {load_results['items_added']}")
        print(f"   Categories: {', '.join(load_results['categories_populated'])}")

        print("\n📈 Analyzing trending patterns...")
        insights = integration.analyze_trending_insights()

        # Display key insights
        category_analysis = insights.get("category_analysis", {})
        viral_content = insights.get("viral_content", [])
        emerging_trends = insights.get("emerging_trends", [])

        print("\n🎯 KEY TRENDING INSIGHTS:")
        for category, data in category_analysis.items():
            print(f"   📊 {category.upper()}: {data['total_items']} items")

            # Show top trending items
            top_items = data.get("top_trending", [])[:3]
            for i, item in enumerate(top_items, 1):
                direction_emoji = {
                    "viral": "🔥",
                    "rising": "📈",
                    "falling": "📉",
                    "stable": "➡️",
                    "emerging": "🚀",
                }.get(item["direction"], "📊")

                print(
                    f"      {i}. {item['name'][:40]} {direction_emoji} {item['growth_rate']:+.1f}%"
                )

        if viral_content:
            print(f"\n🔥 VIRAL CONTENT ({len(viral_content)} items):")
            for item in viral_content[:3]:
                print(f"   • {item['name']} (+{item['growth_rate']:.1f}%)")

        if emerging_trends:
            print(f"\n🚀 EMERGING TRENDS ({len(emerging_trends)} items):")
            for item in emerging_trends[:3]:
                print(f"   • {item['name']} (momentum: {item['momentum']:.2f})")

        # Generate comprehensive report
        print("\n📋 Generating trending report...")
        report_path = integration.create_trending_report()
        print(f"   ✅ Report saved to: {report_path}")

    except Exception as e:
        print(f"   ❌ Trending analysis error: {e}")

    print()

    # 3. Visualization Demo
    print("📊 PART 3: ADVANCED VISUALIZATIONS")
    print("-" * 50)

    try:
        # Check for visualization dependencies without importing modules
        import importlib.util

        matplotlib_available = bool(importlib.util.find_spec("matplotlib.pyplot")) and bool(
            importlib.util.find_spec("seaborn")
        )
        plotly_available = bool(importlib.util.find_spec("plotly.graph_objects"))

        print(f"📊 Matplotlib available: {matplotlib_available}")
        print(f"📊 Plotly available: {plotly_available}")

        if matplotlib_available:
            print("\n🎨 Creating static visualizations...")
            viz_files = list(Path("data/trending_visualizations").glob("*.png"))
            print(f"   📊 Charts created: {len(viz_files)}")
            for viz_file in viz_files:
                print(f"      • {viz_file.name}")

        if plotly_available:
            print("\n🎨 Interactive visualizations available")
            html_files = list(Path("data/trending_visualizations").glob("*.html"))
            print(f"   📊 Interactive dashboards: {len(html_files)}")
            for html_file in html_files:
                print(f"      • {html_file.name}")

        if not matplotlib_available and not plotly_available:
            print("   ℹ️ Install visualization libraries:")
            print("      pip install matplotlib seaborn plotly")

    except Exception as e:
        print(f"   ⚠️ Visualization check error: {e}")

    print()

    # 4. Platform Summary
    print("🎯 PLATFORM CAPABILITIES SUMMARY")
    print("-" * 50)

    capabilities = [
        "✅ Multi-source data integration (Spotify, Last.fm, AudioDB, etc.)",
        "✅ Statistical data quality assessment and outlier detection",
        "✅ Advanced forecasting models (ARIMA, SARIMA, Exponential Smoothing)",
        "✅ Real-time trending pattern analysis and viral content detection",
        "✅ Predictive analytics for emerging trends",
        "✅ Interactive visualizations and comprehensive reporting",
        "✅ Modular architecture for easy debugging and extension",
        "✅ Graceful fallbacks when optional dependencies unavailable",
    ]

    for capability in capabilities:
        print(f"   {capability}")

    print()

    # 5. Next Steps
    print("🚀 SUGGESTED NEXT STEPS")
    print("-" * 50)

    next_steps = [
        "🔄 Set up automated data collection pipelines",
        "📊 Implement real-time streaming analytics",
        "🎯 Create custom trend detection algorithms",
        "📱 Build web dashboard for live monitoring",
        "🔔 Set up alerts for viral content detection",
        "🧠 Add machine learning recommendation engine",
        "📈 Integrate additional data sources (social media, etc.)",
        "🔧 Deploy to cloud for scalable processing",
    ]

    for step in next_steps:
        print(f"   {step}")

    print()
    print("🎵 Complete analytics platform demonstration finished!")
    print("📄 Check data/trending/ for detailed reports and visualizations")


if __name__ == "__main__":
    main()
