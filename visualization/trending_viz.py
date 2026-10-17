"""
Advanced visualization module for trending schema data.
Creates interactive charts and dashboards for trending analysis.
"""

import warnings
from typing import Any, cast

from core.utils import read_json, resolve_project_path

# Avoid heavy imports at module load; import within functions when needed

warnings.filterwarnings("ignore")

try:
    import importlib.util as _ils

    MATPLOTLIB_AVAILABLE = bool(_ils.find_spec("matplotlib.pyplot")) and bool(
        _ils.find_spec("seaborn")
    )
    PLOTLY_AVAILABLE = bool(_ils.find_spec("plotly.graph_objects")) and bool(
        _ils.find_spec("plotly.subplots")
    )
except Exception:
    MATPLOTLIB_AVAILABLE = False
    PLOTLY_AVAILABLE = False


class TrendingVisualizationEngine:
    """Advanced visualization for trending data analysis."""

    def __init__(self, style: str = "seaborn-v0_8-darkgrid"):
        self.style = style
        self.color_palette = {
            "viral": "#FF4444",
            "rising": "#44FF44",
            "falling": "#FF8844",
            "stable": "#4444FF",
            "volatile": "#FF44FF",
            "emerging": "#44FFFF",
            "declining": "#888888",
        }

        if MATPLOTLIB_AVAILABLE:
            import matplotlib.pyplot as plt  # type: ignore
            import seaborn as sns  # type: ignore

            # Use a safe default style if the requested one isn't available
            available_styles = plt.style.available
            if self.style in available_styles:
                plt.style.use(self.style)
            else:
                plt.style.use("default")

            # Set color palette
            colors = list(self.color_palette.values())
            sns.set_palette(colors)

    def plot_trending_timeline(
        self, trending_data: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Create timeline visualization of trending patterns."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for plotting"
        import matplotlib.pyplot as plt  # type: ignore

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle("Trending Analysis Timeline Dashboard", fontsize=16, fontweight="bold")

        # Parse trending data
        categories = trending_data.get("category_analysis", {})
        viral_content = trending_data.get("viral_content", [])
        emerging_trends = trending_data.get("emerging_trends", [])

        # Plot 1: Trending by Category (Bar Chart)
        ax1 = axes[0, 0]
        if categories:
            category_names = list(categories.keys())
            category_counts = [data["total_items"] for data in categories.values()]

            bars = ax1.bar(
                category_names,
                category_counts,
                color=list(self.color_palette.values())[: len(category_names)],
            )
            ax1.set_title("Trending Items by Category")
            ax1.set_ylabel("Number of Items")
            ax1.tick_params(axis="x", rotation=45)

            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax1.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    height,
                    f"{int(height)}",
                    ha="center",
                    va="bottom",
                )

        # Plot 2: Growth Rate Distribution
        ax2 = axes[0, 1]
        all_growth_rates = []
        all_directions = []

        for category_data in categories.values():
            for item in category_data.get("top_trending", []):
                all_growth_rates.append(item["growth_rate"])
                all_directions.append(item["direction"])

        if all_growth_rates:
            # Create scatter plot colored by direction
            unique_directions = list(set(all_directions))
            colors = [self.color_palette.get(direction, "#888888") for direction in all_directions]

            ax2.scatter(range(len(all_growth_rates)), all_growth_rates, c=colors, alpha=0.7, s=60)
            ax2.set_title("Growth Rate Distribution")
            ax2.set_xlabel("Item Index")
            ax2.set_ylabel("Growth Rate (%)")
            ax2.axhline(y=0, color="black", linestyle="--", alpha=0.5)

            # Add legend
            handles = [
                plt.Line2D(
                    [0],
                    [0],
                    marker="o",
                    color="w",
                    markerfacecolor=self.color_palette.get(direction, "#888888"),
                    markersize=8,
                    label=direction.title(),
                )
                for direction in unique_directions
            ]
            ax2.legend(handles=handles, loc="upper right")

        # Plot 3: Viral vs Emerging Comparison
        ax3 = axes[1, 0]
        viral_names = [
            item["name"][:20] + "..." if len(item["name"]) > 20 else item["name"]
            for item in viral_content[:5]
        ]
        viral_growth = [item["growth_rate"] for item in viral_content[:5]]

        emerging_names = [
            item["name"][:20] + "..." if len(item["name"]) > 20 else item["name"]
            for item in emerging_trends[:5]
        ]
        emerging_momentum = [
            item["momentum"] * 100 for item in emerging_trends[:5]
        ]  # Scale for comparison

        if viral_names or emerging_names:
            max_len = max(len(viral_names), len(emerging_names))
            x_pos = list(range(max_len))

            if viral_names:
                ax3.barh(
                    x_pos[: len(viral_names)],
                    viral_growth,
                    color=self.color_palette["viral"],
                    alpha=0.7,
                    label="Viral Content (Growth %)",
                )

            if emerging_names:
                ax3.barh(
                    [v + 0.4 for v in x_pos[: len(emerging_names)]],
                    emerging_momentum,
                    color=self.color_palette["emerging"],
                    alpha=0.7,
                    label="Emerging Trends (Momentum × 100)",
                )

            # Set labels
            all_names = viral_names + emerging_names
            ax3.set_yticks(x_pos[: len(all_names)])
            ax3.set_yticklabels(all_names[: len(x_pos)])
            ax3.set_title("Viral Content vs Emerging Trends")
            ax3.set_xlabel("Growth Rate / Momentum")
            ax3.legend()

        # Plot 4: Trend Direction Summary (Pie Chart)
        ax4 = axes[1, 1]
        direction_counts: dict[str, int] = {}

        for category_data in categories.values():
            for direction, count in category_data.get("directions", {}).items():
                direction_counts[direction] = direction_counts.get(direction, 0) + count

        if direction_counts:
            directions = list(direction_counts.keys())
            counts = list(direction_counts.values())
            colors = [self.color_palette.get(direction, "#888888") for direction in directions]

            wedges, texts, autotexts = ax4.pie(
                counts, labels=directions, colors=colors, autopct="%1.1f%%", startangle=90
            )
            ax4.set_title("Overall Trend Direction Distribution")

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📊 Trending timeline saved to {save_path}")

        plt.show()
        return "Trending timeline visualization complete"

    def create_interactive_trending_dashboard(
        self, trending_data: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Create interactive trending dashboard using Plotly."""
        if not PLOTLY_AVAILABLE:
            return "Plotly not available for interactive dashboard"
        # Local imports to avoid heavy module load at import time
        import pandas as pd  # type: ignore
        import plotly.graph_objects as go  # type: ignore
        from plotly.subplots import make_subplots  # type: ignore

        # Create subplots
        fig = make_subplots(
            rows=3,
            cols=2,
            subplot_titles=(
                "Category Overview",
                "Growth Rate Trends",
                "Viral Content Performance",
                "Emerging Trends Momentum",
                "Trend Direction Distribution",
                "Top Movers Summary",
            ),
            specs=[
                [{"type": "bar"}, {"type": "scatter"}],
                [{"type": "bar"}, {"type": "bar"}],
                [{"type": "pie"}, {"type": "table"}],
            ],
        )

        categories = trending_data.get("category_analysis", {})
        viral_content = trending_data.get("viral_content", [])
        emerging_trends = trending_data.get("emerging_trends", [])

        # Plot 1: Category Overview
        if categories:
            category_names = list(categories.keys())
            category_counts = [data["total_items"] for data in categories.values()]

            fig.add_trace(
                go.Bar(
                    x=category_names,
                    y=category_counts,
                    name="Items by Category",
                    marker_color="lightblue",
                ),
                row=1,
                col=1,
            )

        # Plot 2: Growth Rate Trends
        all_items = []
        for category, data in categories.items():
            for item in data.get("top_trending", []):
                all_items.append(
                    {
                        "name": item["name"],
                        "category": category,
                        "growth_rate": item["growth_rate"],
                        "trend_strength": item["trend_strength"],
                        "direction": item["direction"],
                    }
                )

        if all_items:
            df_items = pd.DataFrame(all_items)

            fig.add_trace(
                go.Scatter(
                    x=df_items["trend_strength"],
                    y=df_items["growth_rate"],
                    mode="markers",
                    marker=dict(size=10, opacity=0.7),
                    text=df_items["name"],
                    name="Trending Items",
                    hovertemplate="<b>%{text}</b><br>"
                    + "Growth Rate: %{y:.1f}%<br>"
                    + "Trend Strength: %{x:.2f}<br>"
                    + "<extra></extra>",
                ),
                row=1,
                col=2,
            )

        # Plot 3: Viral Content Performance
        if viral_content:
            viral_names = [item["name"][:30] for item in viral_content[:10]]
            viral_growth = [item["growth_rate"] for item in viral_content[:10]]

            fig.add_trace(
                go.Bar(
                    x=viral_growth,
                    y=viral_names,
                    orientation="h",
                    name="Viral Growth",
                    marker_color="red",
                ),
                row=2,
                col=1,
            )

        # Plot 4: Emerging Trends Momentum
        if emerging_trends:
            emerging_names = [item["name"][:30] for item in emerging_trends[:10]]
            emerging_momentum = [item["momentum"] for item in emerging_trends[:10]]

            fig.add_trace(
                go.Bar(
                    x=emerging_momentum,
                    y=emerging_names,
                    orientation="h",
                    name="Emerging Momentum",
                    marker_color="cyan",
                ),
                row=2,
                col=2,
            )

        # Plot 5: Trend Direction Distribution
        direction_counts: dict[str, int] = {}
        for category_data in categories.values():
            for direction, count in category_data.get("directions", {}).items():
                direction_counts[direction] = direction_counts.get(direction, 0) + count

        if direction_counts:
            fig.add_trace(
                go.Pie(
                    labels=list(direction_counts.keys()),
                    values=list(direction_counts.values()),
                    name="Trend Directions",
                ),
                row=3,
                col=1,
            )

        # Plot 6: Top Movers Table
        if all_items:
            top_movers = sorted(all_items, key=lambda x: abs(x["growth_rate"]), reverse=True)[:10]

            fig.add_trace(
                go.Table(
                    header=dict(
                        values=["Name", "Category", "Direction", "Growth Rate"],
                        fill_color="lightgray",
                    ),
                    cells=dict(
                        values=[
                            [item["name"][:25] for item in top_movers],
                            [item["category"] for item in top_movers],
                            [item["direction"] for item in top_movers],
                            [f"{item['growth_rate']:.1f}%" for item in top_movers],
                        ],
                        fill_color="white",
                    ),
                ),
                row=3,
                col=2,
            )

        # Update layout
        fig.update_layout(
            title_text="Spotify Trending Analysis Dashboard",
            title_x=0.5,
            height=1200,
            showlegend=False,
        )

        # Update axes labels
        fig.update_xaxes(title_text="Categories", row=1, col=1)
        fig.update_yaxes(title_text="Number of Items", row=1, col=1)

        fig.update_xaxes(title_text="Trend Strength", row=1, col=2)
        fig.update_yaxes(title_text="Growth Rate (%)", row=1, col=2)

        fig.update_xaxes(title_text="Growth Rate (%)", row=2, col=1)
        fig.update_xaxes(title_text="Momentum", row=2, col=2)

        if save_path:
            fig.write_html(save_path)
            print(f"📊 Interactive dashboard saved to {save_path}")

        fig.show()
        return "Interactive trending dashboard created successfully"

    def plot_trending_heatmap(
        self, time_series_data: dict[str, list], save_path: str | None = None
    ) -> str:
        """Create heatmap visualization of trending patterns over time."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for heatmap"
        # Local imports
        import matplotlib.pyplot as plt  # type: ignore
        import numpy as np  # type: ignore
        import pandas as pd  # type: ignore
        import seaborn as sns  # type: ignore

        if not time_series_data:
            return "No time series data provided"

        # Convert to DataFrame for heatmap
        df = pd.DataFrame(time_series_data)

        if df.empty:
            return "Empty time series data"

        # Create heatmap
        plt.figure(figsize=(14, 8))

        # Use correlation if numeric data, otherwise use value counts
        if df.select_dtypes(include=[np.number]).shape[1] > 0:
            numeric_df = df.select_dtypes(include=[np.number])
            heatmap_data = numeric_df.corr()
            title = "Trending Correlation Heatmap"
        else:
            # Create frequency heatmap for categorical data
            heatmap_data = df.apply(pd.value_counts).fillna(0)
            title = "Trending Frequency Heatmap"

        sns.heatmap(heatmap_data, annot=True, cmap="viridis", center=0, square=True, linewidths=0.5)

        plt.title(title, fontsize=14, fontweight="bold")
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📊 Trending heatmap saved to {save_path}")

        plt.show()
        return "Trending heatmap visualization complete"

    def create_trend_prediction_chart(
        self, predictions: dict[str, Any], save_path: str | None = None
    ) -> str:
        """Create visualization for trend predictions."""
        if not MATPLOTLIB_AVAILABLE:
            return "Matplotlib not available for plotting"
        # Local imports
        import matplotlib.pyplot as plt  # type: ignore
        import numpy as np  # type: ignore

        if not predictions:
            return "No prediction data provided"

        fig, axes = plt.subplots(2, 2, figsize=(16, 10))
        fig.suptitle("Trend Prediction Analysis", fontsize=16, fontweight="bold")

        prediction_items = list(predictions.items())[:4]  # Take first 4 predictions

        for i, (item_id, prediction) in enumerate(prediction_items):
            row = i // 2
            col = i % 2
            ax = axes[row, col]

            # Plot predictions
            predictions_data = prediction.get("predictions", [])
            if predictions_data:
                x_range = range(len(predictions_data))

                # Plot prediction line
                ax.plot(
                    x_range,
                    predictions_data,
                    color=self.color_palette.get(
                        prediction.get("expected_direction", "stable"), "blue"
                    ),
                    linewidth=2,
                    marker="o",
                    label="Predicted Values",
                )

                # Add confidence band
                confidence = prediction.get("confidence", 0)
                std_dev = np.std(predictions_data) * (1 - confidence)

                upper_band = np.array(predictions_data) + std_dev
                lower_band = np.array(predictions_data) - std_dev

                ax.fill_between(
                    x_range,
                    lower_band,
                    upper_band,
                    alpha=0.3,
                    color=self.color_palette.get(
                        prediction.get("expected_direction", "stable"), "blue"
                    ),
                )

                # Formatting
                ax.set_title(f"{item_id[:20]}...")
                ax.set_xlabel("Time Periods Ahead")
                ax.set_ylabel("Predicted Value")
                ax.grid(True, alpha=0.3)

                # Add annotation
                direction = prediction.get("expected_direction", "unknown")
                confidence_pct = confidence * 100
                ax.text(
                    0.05,
                    0.95,
                    f"Direction: {direction}\nConfidence: {confidence_pct:.0f}%",
                    transform=ax.transAxes,
                    verticalalignment="top",
                    bbox=dict(boxstyle="round", facecolor="white", alpha=0.8),
                )

        # Hide empty subplots
        for i in range(len(prediction_items), 4):
            row = i // 2
            col = i % 2
            axes[row, col].set_visible(False)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"📊 Trend predictions saved to {save_path}")

        plt.show()
        return f"Trend prediction visualization complete ({len(prediction_items)} items)"


def visualize_trending_report(report_file: str, output_dir: str = "data/trending/visualizations"):
    """Create comprehensive visualizations from trending report."""
    print("🎨 Creating comprehensive trending visualizations...")

    report_data = read_json(report_file)
    trending_insights = report_data.get("trending_insights", {})

    output_path = resolve_project_path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize visualization engine
    viz_engine = TrendingVisualizationEngine()

    visualizations_created = []

    # Create timeline dashboard
    if MATPLOTLIB_AVAILABLE:
        timeline_path = output_path / "trending_timeline_dashboard.png"
        result = viz_engine.plot_trending_timeline(trending_insights, str(timeline_path))
        if "complete" in result:
            visualizations_created.append("timeline_dashboard")

    # Create interactive dashboard
    if PLOTLY_AVAILABLE:
        interactive_path = output_path / "interactive_trending_dashboard.html"
        result = viz_engine.create_interactive_trending_dashboard(
            trending_insights, str(interactive_path)
        )
        if "successfully" in result:
            visualizations_created.append("interactive_dashboard")

    # Create prediction charts if available
    predictions = trending_insights.get("predictions", {})
    if predictions and MATPLOTLIB_AVAILABLE:
        prediction_path = output_path / "trend_predictions.png"
        result = viz_engine.create_trend_prediction_chart(predictions, str(prediction_path))
        if "complete" in result:
            visualizations_created.append("trend_predictions")

    print(f"✅ Created {len(visualizations_created)} visualizations:")
    for viz in visualizations_created:
        print(f"   📊 {viz}")

    return output_path


if __name__ == "__main__":
    print("🎨 Testing Trending Visualization Engine")
    print("=" * 50)

    # Create sample trending data
    sample_data = {
        "category_analysis": {
            "artist": {
                "total_items": 15,
                "directions": {"rising": 8, "viral": 3, "stable": 4},
                "top_trending": [
                    {
                        "name": "Viral Artist",
                        "direction": "viral",
                        "growth_rate": 150.5,
                        "trend_strength": 0.9,
                    },
                    {
                        "name": "Rising Star",
                        "direction": "rising",
                        "growth_rate": 45.2,
                        "trend_strength": 0.8,
                    },
                    {
                        "name": "Steady Performer",
                        "direction": "stable",
                        "growth_rate": 5.1,
                        "trend_strength": 0.6,
                    },
                ],
            },
            "track": {
                "total_items": 22,
                "directions": {"rising": 12, "falling": 6, "stable": 4},
                "top_trending": [
                    {
                        "name": "Hit Song",
                        "direction": "rising",
                        "growth_rate": 89.3,
                        "trend_strength": 0.85,
                    },
                    {
                        "name": "Fading Track",
                        "direction": "falling",
                        "growth_rate": -23.1,
                        "trend_strength": 0.7,
                    },
                ],
            },
        },
        "viral_content": [
            {
                "name": "Breakout Artist",
                "category": "artist",
                "growth_rate": 200.5,
                "peak_value": 5000,
            },
            {"name": "Viral Hit", "category": "track", "growth_rate": 175.8, "peak_value": 8500},
        ],
        "emerging_trends": [
            {
                "name": "New Genre Pioneer",
                "category": "artist",
                "momentum": 0.85,
                "trend_strength": 0.75,
            },
            {
                "name": "Underground Hit",
                "category": "track",
                "momentum": 0.72,
                "trend_strength": 0.68,
            },
        ],
        "predictions": {
            "artist_1": {
                "predictions": [1000, 1100, 1250, 1400, 1600, 1800, 2000],
                "confidence": 0.82,
                "expected_direction": "rising",
            },
            "track_1": {
                "predictions": [800, 750, 700, 650, 600, 550, 500],
                "confidence": 0.75,
                "expected_direction": "falling",
            },
        },
    }

    # Test visualizations
    viz_engine = TrendingVisualizationEngine()

    if MATPLOTLIB_AVAILABLE:
        print("📊 Testing timeline dashboard...")
        viz_engine.plot_trending_timeline(sample_data)

        print("📊 Testing prediction charts...")
    viz_engine.create_trend_prediction_chart(cast(dict[str, Any], sample_data["predictions"]))

    if PLOTLY_AVAILABLE:
        print("📊 Testing interactive dashboard...")
        viz_engine.create_interactive_trending_dashboard(sample_data)

    print("🎨 Trending visualization testing complete!")
