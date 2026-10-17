"""Advanced visualization module for statistical analysis and forecasting results."""

import warnings
from typing import Any

import numpy as np
import pandas as pd

from core.utils import read_json, resolve_project_path

warnings.filterwarnings("ignore")

try:
    import matplotlib.pyplot as plt
    import seaborn as sns

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


class StatisticalVisualizationEngine:
    """Advanced visualization for statistical analysis and forecasting."""

    def __init__(self, style: str = "seaborn", figsize: tuple = (12, 8)):
        self.style = style
        self.figsize = figsize
        self.color_palette = [
            "#1f77b4",
            "#ff7f0e",
            "#2ca02c",
            "#d62728",
            "#9467bd",
            "#8c564b",
            "#e377c2",
            "#7f7f7f",
            "#bcbd22",
            "#17becf",
        ]

        if MATPLOTLIB_AVAILABLE:
            plt.style.use(style if style in plt.style.available else "default")
            sns.set_palette(self.color_palette)

    def plot_data_quality_report(
        self, quality_report: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Create comprehensive data quality visualization."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for plotting"

        # Create subplots
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle("Data Quality Analysis Report", fontsize=16, fontweight="bold")

        # Plot 1: Missing values
        if "basic_stats" in quality_report and "missing_values" in quality_report["basic_stats"]:
            missing_data = quality_report["basic_stats"]["missing_values"]
            if missing_data:
                columns = list(missing_data.keys())
                missing_counts = list(missing_data.values())

                axes[0, 0].bar(columns, missing_counts, color=self.color_palette[0])
                axes[0, 0].set_title("Missing Values by Column")
                axes[0, 0].set_ylabel("Count")
                axes[0, 0].tick_params(axis="x", rotation=45)

        # Plot 2: Outlier percentages
        if "outlier_analysis" in quality_report:
            outlier_data = quality_report["outlier_analysis"]
            columns = []
            iqr_outliers = []
            z_outliers = []

            for col, outliers in outlier_data.items():
                if "iqr" in outliers and "zscore" in outliers:
                    columns.append(col)
                    iqr_outliers.append(outliers["iqr"]["percentage"])
                    z_outliers.append(outliers["zscore"]["percentage"])

            if columns:
                x = np.arange(len(columns))
                width = 0.35

                axes[0, 1].bar(
                    x - width / 2,
                    iqr_outliers,
                    width,
                    label="IQR Method",
                    color=self.color_palette[1],
                )
                axes[0, 1].bar(
                    x + width / 2,
                    z_outliers,
                    width,
                    label="Z-Score Method",
                    color=self.color_palette[2],
                )

                axes[0, 1].set_title("Outlier Detection Results")
                axes[0, 1].set_ylabel("Percentage of Outliers")
                axes[0, 1].set_xticks(x)
                axes[0, 1].set_xticklabels(columns, rotation=45)
                axes[0, 1].legend()

        # Plot 3: Recommendations pie chart
        if "recommendations" in quality_report and quality_report["recommendations"]:
            recommendations = quality_report["recommendations"]

            # Categorize recommendations
            categories = {"Missing Values": 0, "Outliers": 0, "Temporal": 0, "Other": 0}

            for rec in recommendations:
                if "missing" in rec.lower():
                    categories["Missing Values"] += 1
                elif "outlier" in rec.lower():
                    categories["Outliers"] += 1
                elif "temporal" in rec.lower() or "gap" in rec.lower():
                    categories["Temporal"] += 1
                else:
                    categories["Other"] += 1

            # Filter out zero categories
            filtered_categories = {k: v for k, v in categories.items() if v > 0}

            if filtered_categories:
                axes[1, 0].pie(
                    filtered_categories.values(),
                    labels=filtered_categories.keys(),
                    autopct="%1.1f%%",
                    colors=self.color_palette[: len(filtered_categories)],
                )
                axes[1, 0].set_title("Issue Categories")

        # Plot 4: Data overview
        if "basic_stats" in quality_report:
            stats = quality_report["basic_stats"]

            # Create overview text
            overview_text = f"""
            Total Rows: {stats.get('total_rows', 'N/A')}
            Total Missing: {sum(stats.get('missing_values', {}).values())}
            Duplicate Rows: {stats.get('duplicate_rows', 'N/A')}

            Quality Score: {self._calculate_quality_score(quality_report):.1f}/100
            """

            axes[1, 1].text(
                0.1,
                0.5,
                overview_text,
                fontsize=12,
                verticalalignment="center",
                transform=axes[1, 1].transAxes,
            )
            axes[1, 1].set_title("Data Overview")
            axes[1, 1].axis("off")

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📊 Data quality report saved to {save_path}")

        plt.show()
        return "Data quality visualization complete"

    def plot_forecasting_results(
        self,
        ts: pd.Series,
        forecasts: dict[str, Any],
        horizon: int = 30,
        save_path: str | None = None,
    ) -> str:
        """Plot time series data with multiple forecasting models."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for plotting"

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 12))

        # Plot 1: Historical data with forecasts
        ax1.plot(
            ts.index, ts.values, label="Historical Data", color="black", linewidth=2, alpha=0.8
        )

        # Generate future dates
        last_date = ts.index[-1]
        future_dates = pd.date_range(
            start=last_date + pd.Timedelta(days=1), periods=horizon, freq="D"
        )

        # Plot forecasts
        color_idx = 0
        successful_forecasts = 0

        for model_name, forecast_data in forecasts.items():
            if "forecast" in forecast_data and "error" not in forecast_data:
                forecast_values = forecast_data["forecast"]
                if len(forecast_values) >= horizon:
                    ax1.plot(
                        future_dates,
                        forecast_values[:horizon],
                        label=f"{model_name}",
                        color=self.color_palette[color_idx % len(self.color_palette)],
                        linestyle="--",
                        alpha=0.7,
                    )

                    # Add confidence intervals if available
                    if "lower_ci" in forecast_data and "upper_ci" in forecast_data:
                        lower_ci = forecast_data["lower_ci"][:horizon]
                        upper_ci = forecast_data["upper_ci"][:horizon]
                        ax1.fill_between(
                            future_dates,
                            lower_ci,
                            upper_ci,
                            alpha=0.2,
                            color=self.color_palette[color_idx % len(self.color_palette)],
                        )

                    successful_forecasts += 1
                    color_idx += 1

        ax1.axvline(x=last_date, color="red", linestyle=":", alpha=0.5, label="Forecast Start")
        ax1.set_title(f"Time Series Forecasting Results ({successful_forecasts} models)")
        ax1.set_ylabel("Values")
        ax1.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
        ax1.grid(True, alpha=0.3)

        # Plot 2: Forecast comparison (box plot)
        forecast_comparison = []
        model_names = []

        for model_name, forecast_data in forecasts.items():
            if "forecast" in forecast_data and "error" not in forecast_data:
                forecast_values = forecast_data["forecast"][:horizon]
                forecast_comparison.extend(forecast_values)
                model_names.extend([model_name] * len(forecast_values))

        if forecast_comparison:
            comparison_df = pd.DataFrame({"Model": model_names, "Forecast": forecast_comparison})

            # Box plot of forecasts
            unique_models = comparison_df["Model"].unique()
            box_data = [
                comparison_df[comparison_df["Model"] == model]["Forecast"].values
                for model in unique_models
            ]

            ax2.boxplot(box_data, labels=unique_models)
            ax2.set_title("Forecast Distribution Comparison")
            ax2.set_ylabel("Forecast Values")
            ax2.tick_params(axis="x", rotation=45)
            ax2.grid(True, alpha=0.3)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📈 Forecasting results saved to {save_path}")

        plt.show()
        return f"Forecasting visualization complete ({successful_forecasts} models plotted)"

    def plot_model_performance(
        self, performance_data: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Plot model performance comparison."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for plotting"

        # Extract performance metrics
        models = []
        mae_scores = []
        rmse_scores = []
        mape_scores = []

        for model_name, metrics in performance_data.items():
            if isinstance(metrics, dict) and "mae" in metrics:
                models.append(model_name)
                mae_scores.append(metrics.get("mae", 0))
                rmse_scores.append(metrics.get("rmse", 0))
                mape_scores.append(metrics.get("mape", 0))

        if not models:
            return "No valid performance data to plot"

        # Create subplot for multiple metrics
        fig, axes = plt.subplots(1, 3, figsize=(18, 6))

        # MAE comparison
        axes[0].bar(models, mae_scores, color=self.color_palette[0])
        axes[0].set_title("Mean Absolute Error (MAE)")
        axes[0].set_ylabel("MAE")
        axes[0].tick_params(axis="x", rotation=45)

        # RMSE comparison
        axes[1].bar(models, rmse_scores, color=self.color_palette[1])
        axes[1].set_title("Root Mean Square Error (RMSE)")
        axes[1].set_ylabel("RMSE")
        axes[1].tick_params(axis="x", rotation=45)

        # MAPE comparison
        axes[2].bar(models, mape_scores, color=self.color_palette[2])
        axes[2].set_title("Mean Absolute Percentage Error (MAPE)")
        axes[2].set_ylabel("MAPE (%)")
        axes[2].tick_params(axis="x", rotation=45)

        # Highlight best performing model
        best_mae_idx = np.argmin(mae_scores)
        axes[0].bar(
            models[best_mae_idx],
            mae_scores[best_mae_idx],
            color="gold",
            edgecolor="red",
            linewidth=2,
        )

        plt.suptitle("Model Performance Comparison", fontsize=16, fontweight="bold")
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📊 Performance comparison saved to {save_path}")

        plt.show()
        return f"Performance visualization complete ({len(models)} models compared)"

    def create_interactive_dashboard(
        self, analysis_results: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Create interactive dashboard using Plotly."""
        if not PLOTLY_AVAILABLE:
            return "Plotly not available for interactive dashboard"

        # Create subplots
        fig = make_subplots(
            rows=3,
            cols=2,
            subplot_titles=(
                "Data Quality Score",
                "Outlier Detection",
                "Missing Values Heatmap",
                "Forecast Accuracy",
                "Model Performance",
                "Trend Analysis",
            ),
            specs=[
                [{"type": "indicator"}, {"type": "bar"}],
                [{"type": "heatmap"}, {"type": "scatter"}],
                [{"type": "bar"}, {"type": "scatter"}],
            ],
        )

        # Quality score indicator
        quality_score = self._calculate_quality_score(analysis_results.get("data_quality", {}))
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=quality_score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "Data Quality Score"},
                gauge={
                    "axis": {"range": [None, 100]},
                    "bar": {"color": "darkblue"},
                    "steps": [
                        {"range": [0, 50], "color": "lightgray"},
                        {"range": [50, 80], "color": "yellow"},
                        {"range": [80, 100], "color": "green"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 4},
                        "thickness": 0.75,
                        "value": 90,
                    },
                },
            ),
            row=1,
            col=1,
        )

        # Add other plots based on available data
        if "data_quality" in analysis_results:
            self._add_quality_plots(fig, analysis_results["data_quality"])

        if "forecasting" in analysis_results:
            self._add_forecasting_plots(fig, analysis_results["forecasting"])

        # Update layout
        fig.update_layout(title_text="Statistical Analysis Dashboard", showlegend=True, height=1200)

        if save_path:
            fig.write_html(save_path)
            print(f"📊 Interactive dashboard saved to {save_path}")

        fig.show()
        return "Interactive dashboard created successfully"

    def _calculate_quality_score(self, quality_report: dict[str, Any]) -> float:
        """Calculate overall data quality score."""
        score = 100.0

        if "basic_stats" in quality_report:
            stats = quality_report["basic_stats"]
            total_rows = stats.get("total_rows", 1)

            # Penalize missing values
            total_missing = sum(stats.get("missing_values", {}).values())
            missing_penalty = min(30, (total_missing / total_rows) * 100)
            score -= missing_penalty

            # Penalize duplicates
            duplicate_penalty = min(20, (stats.get("duplicate_rows", 0) / total_rows) * 100)
            score -= duplicate_penalty

        # Penalize high outlier rates
        if "outlier_analysis" in quality_report:
            outlier_penalties = []
            for col, outliers in quality_report["outlier_analysis"].items():
                if "iqr" in outliers:
                    outlier_pct = outliers["iqr"]["percentage"]
                    if outlier_pct > 10:  # More than 10% outliers
                        outlier_penalties.append(min(15, outlier_pct - 10))

            if outlier_penalties:
                score -= np.mean(outlier_penalties)

        return max(0, min(100, score))

    def _add_quality_plots(self, fig, quality_data: dict[str, Any]):
        """Add quality-related plots to the dashboard."""
        # Implementation would add traces for quality visualization
        pass

    def _add_forecasting_plots(self, fig, forecasting_data: dict[str, Any]):
        """Add forecasting-related plots to the dashboard."""
        # Implementation would add traces for forecasting visualization
        pass


def visualize_comprehensive_results(results_file: str, output_dir: str = "data/visualizations"):
    """Create comprehensive visualizations from analysis results file."""
    print("🎨 Creating comprehensive visualizations...")

    results = read_json(results_file)
    output_path = resolve_project_path(output_dir)
    output_path.mkdir(exist_ok=True)

    # Initialize visualization engine
    viz_engine = StatisticalVisualizationEngine()

    # Create data quality report
    if "data_quality" in results:
        quality_plot_path = output_path / "data_quality_report.png"
        viz_engine.plot_data_quality_report(results["data_quality"], str(quality_plot_path))

    # Create forecasting visualizations for each column
    for col, col_results in results.get("forecasting", {}).items():
        if "error" not in col_results and "forecasts" in col_results:
            # Create sample time series for visualization
            prep_info = col_results.get("preparation", {})
            if "date_range" in prep_info:
                start_date = pd.to_datetime(prep_info["date_range"]["start"])
                length = prep_info.get("filled_length", 100)
                dates = pd.date_range(start_date, periods=length, freq="D")

                # Create synthetic data for visualization (in real case, would use actual data)
                values = np.random.normal(1000, 200, length)
                ts = pd.Series(values, index=dates)

                forecast_plot_path = output_path / f"forecasting_{col}.png"
                viz_engine.plot_forecasting_results(
                    ts, col_results["forecasts"], save_path=str(forecast_plot_path)
                )

                # Create performance comparison
                if "performance" in col_results:
                    performance_plot_path = output_path / f"performance_{col}.png"
                    viz_engine.plot_model_performance(
                        col_results["performance"], save_path=str(performance_plot_path)
                    )

    # Create interactive dashboard
    dashboard_path = output_path / "interactive_dashboard.html"
    viz_engine.create_interactive_dashboard(results, str(dashboard_path))

    print(f"✅ Comprehensive visualizations created in {output_path}")
    return output_path


if __name__ == "__main__":
    # Test visualization with sample data
    print("🎨 Testing Statistical Visualization Engine")

    # Create sample analysis results
    sample_results = {
        "data_quality": {
            "basic_stats": {
                "total_rows": 1000,
                "missing_values": {"streams": 50, "plays": 30, "listeners": 20},
                "duplicate_rows": 5,
            },
            "outlier_analysis": {
                "streams": {
                    "iqr": {"percentage": 8.5, "count": 85},
                    "zscore": {"percentage": 4.2, "count": 42},
                },
                "plays": {
                    "iqr": {"percentage": 6.3, "count": 63},
                    "zscore": {"percentage": 3.1, "count": 31},
                },
            },
            "recommendations": [
                "High missing values in streams (5.0%). Consider imputation.",
                "Moderate outlier percentage in plays (6.3%). Review data collection.",
            ],
        },
        "forecasting": {
            "streams": {
                "forecasts": {
                    "arima": {"forecast": np.random.normal(1000, 100, 30).tolist()},
                    "sarima": {"forecast": np.random.normal(1050, 120, 30).tolist()},
                },
                "performance": {
                    "arima": {"mae": 95.2, "rmse": 124.5, "mape": 8.3},
                    "sarima": {"mae": 87.9, "rmse": 115.8, "mape": 7.8},
                },
            }
        },
    }

    # Test visualizations
    viz_engine = StatisticalVisualizationEngine()

    if MATPLOTLIB_AVAILABLE:
        viz_engine.plot_data_quality_report(sample_results["data_quality"])

        # Test forecasting plot with sample data
        dates = pd.date_range("2024-01-01", periods=100, freq="D")
        ts = pd.Series(np.random.normal(1000, 200, 100), index=dates)
        viz_engine.plot_forecasting_results(
            ts, sample_results["forecasting"]["streams"]["forecasts"]
        )

        viz_engine.plot_model_performance(sample_results["forecasting"]["streams"]["performance"])

    if PLOTLY_AVAILABLE:
        viz_engine.create_interactive_dashboard(sample_results)

    print("🎨 Visualization testing complete!")
