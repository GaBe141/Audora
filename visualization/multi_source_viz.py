"""Multi-source visualization generator for comprehensive music data analysis."""

import warnings
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from core.utils import resolve_project_path, save_matplotlib_figure

warnings.filterwarnings("ignore")

# Set style
plt.style.use("default")
sns.set_palette("husl")


class MultiSourceVisualizer:
    """Create comprehensive visualizations from multi-source music data."""

    def __init__(self, all_data: dict[str, pd.DataFrame], insights: dict[str, Any]):
        self.all_data = all_data
        self.insights = insights
        self.output_dir = resolve_project_path("data")
        self.output_dir.mkdir(exist_ok=True)

    def create_mainstream_comparison(self):
        """Create visualization comparing mainstream scores across platforms."""
        if not self.insights.get("mainstream_analysis"):
            return

        mainstream = self.insights["mainstream_analysis"]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Bar chart of mainstream scores
        platforms = ["Spotify Charts", "Last.fm Global", "Average"]
        scores = [
            mainstream["spotify_charts_mainstream_percent"],
            mainstream["lastfm_mainstream_percent"],
            mainstream["average_mainstream_score"],
        ]
        colors = ["#1DB954", "#D51007", "#FF6B35"]

        bars = ax1.bar(platforms, scores, color=colors, alpha=0.8)
        ax1.set_title("Mainstream Score Comparison", fontsize=16, fontweight="bold")
        ax1.set_ylabel("Mainstream Score (%)")
        ax1.set_ylim(0, 100)

        # Add value labels on bars
        for bar, score in zip(bars, scores, strict=False):
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1,
                f"{score:.1f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # Gauge chart for overall mainstream score
        avg_score = mainstream["average_mainstream_score"]

        # Create a simple gauge using a pie chart
        sizes = [avg_score, 100 - avg_score]
        colors_gauge = ["#FF6B35", "#E8E8E8"]
        wedges, texts = ax2.pie(sizes, colors=colors_gauge, startangle=90, counterclock=False)

        # Add center circle to make it look like a gauge
        centre_circle = plt.Circle((0, 0), 0.70, fc="white")
        ax2.add_artist(centre_circle)

        # Add text in center
        ax2.text(
            0,
            0,
            f"{avg_score:.1f}%\nMainstream",
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold",
        )
        ax2.set_title("Overall Mainstream Score", fontsize=16, fontweight="bold")

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "mainstream_analysis.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created mainstream comparison visualization")

    def create_geographic_diversity_map(self):
        """Create geographic diversity visualization."""
        if not self.insights.get("geographic_diversity"):
            return

        geo = self.insights["geographic_diversity"]
        if not geo["country_distribution"]:
            return

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

        # Top countries bar chart
        countries = list(geo["country_distribution"].keys())[:10]  # Top 10
        counts = list(geo["country_distribution"].values())[:10]

        bars = ax1.barh(
            range(len(countries)), counts, color=plt.cm.viridis(np.linspace(0, 1, len(countries)))
        )
        ax1.set_yticks(range(len(countries)))
        ax1.set_yticklabels(countries)
        ax1.set_xlabel("Number of Artists")
        ax1.set_title("Artist Distribution by Country", fontsize=16, fontweight="bold")
        ax1.invert_yaxis()

        # Add value labels
        for i, (bar, count) in enumerate(zip(bars, counts, strict=False)):
            ax1.text(count + 0.1, i, str(count), va="center", fontweight="bold")

        # Diversity pie chart
        if len(countries) > 5:
            # Group smaller countries
            top_5_countries = countries[:5]
            top_5_counts = counts[:5]
            other_count = sum(counts[5:])

            pie_countries = top_5_countries + ["Others"]
            pie_counts = top_5_counts + [other_count]
        else:
            pie_countries = countries
            pie_counts = counts

        colors = plt.cm.Set3(np.linspace(0, 1, len(pie_countries)))
        wedges, texts, autotexts = ax2.pie(
            pie_counts, labels=pie_countries, autopct="%1.1f%%", colors=colors, startangle=90
        )
        ax2.set_title("Geographic Diversity Distribution", fontsize=16, fontweight="bold")

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "geographic_diversity.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created geographic diversity visualization")

    def create_era_timeline(self):
        """Create timeline visualization of artist eras."""
        if "genre_evolution" not in self.all_data or self.all_data["genre_evolution"].empty:
            return

        careers_df = self.all_data["genre_evolution"].copy()
        careers_df["formed_year"] = pd.to_numeric(careers_df["formed_year"], errors="coerce")
        careers_df = careers_df.dropna(subset=["formed_year"])

        if careers_df.empty:
            return

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))

        # Timeline scatter plot
        y_positions = range(len(careers_df))
        plt.cm.plasma(np.linspace(0, 1, len(careers_df)))

        scatter = ax1.scatter(
            careers_df["formed_year"],
            y_positions,
            c=careers_df["formed_year"],
            cmap="plasma",
            s=100,
            alpha=0.7,
            edgecolors="black",
            linewidth=0.5,
        )

        # Add artist names
        for i, (_, row) in enumerate(careers_df.iterrows()):
            ax1.annotate(
                row["artist_name"],
                (row["formed_year"], i),
                xytext=(5, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
            )

        ax1.set_xlabel("Formation Year")
        ax1.set_ylabel("Artists")
        ax1.set_title("Artist Formation Timeline", fontsize=16, fontweight="bold")
        ax1.grid(True, alpha=0.3)

        # Colorbar
        cbar = plt.colorbar(scatter, ax=ax1)
        cbar.set_label("Formation Year")

        # Decade distribution
        careers_df["decade"] = (careers_df["formed_year"] // 10) * 10
        decade_counts = careers_df["decade"].value_counts().sort_index()

        bars = ax2.bar(
            decade_counts.index,
            decade_counts.values,
            width=8,
            alpha=0.8,
            color="skyblue",
            edgecolor="navy",
        )
        ax2.set_xlabel("Decade")
        ax2.set_ylabel("Number of Artists")
        ax2.set_title("Artists by Decade of Formation", fontsize=16, fontweight="bold")
        ax2.set_xticks(decade_counts.index)
        ax2.set_xticklabels([f"{int(d)}s" for d in decade_counts.index])

        # Add value labels
        for bar, count in zip(bars, decade_counts.values, strict=False):
            ax2.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.1,
                str(count),
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "era_timeline.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created era timeline visualization")

    def create_network_analysis(self):
        """Create artist relationship network visualization."""
        if (
            "artist_relationships" not in self.all_data
            or self.all_data["artist_relationships"].empty
        ):
            return

        relationships_df = self.all_data["artist_relationships"]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        # Relationship types distribution
        if (
            "relationship_summary" in self.all_data
            and not self.all_data["relationship_summary"].empty
        ):
            rel_summary = self.all_data["relationship_summary"]

            bars = ax1.bar(
                rel_summary["relationship_type"],
                rel_summary["count"],
                color=plt.cm.Set2(np.linspace(0, 1, len(rel_summary))),
            )
            ax1.set_title("Artist Relationship Types", fontsize=16, fontweight="bold")
            ax1.set_ylabel("Number of Relationships")
            ax1.tick_params(axis="x", rotation=45)

            # Add value labels
            for bar, count in zip(bars, rel_summary["count"], strict=False):
                ax1.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.1,
                    str(count),
                    ha="center",
                    va="bottom",
                    fontweight="bold",
                )

        # Connection count by artist
        source_counts = relationships_df["source_artist"].value_counts()
        target_counts = relationships_df["target_artist"].value_counts()
        all_connections = source_counts.add(target_counts, fill_value=0).sort_values(
            ascending=False
        )

        top_connected = all_connections.head(10)

        bars = ax2.barh(
            range(len(top_connected)),
            top_connected.values,
            color=plt.cm.viridis(np.linspace(0, 1, len(top_connected))),
        )
        ax2.set_yticks(range(len(top_connected)))
        ax2.set_yticklabels(top_connected.index)
        ax2.set_xlabel("Number of Connections")
        ax2.set_title("Most Connected Artists", fontsize=16, fontweight="bold")
        ax2.invert_yaxis()

        # Add value labels
        for i, (bar, count) in enumerate(zip(bars, top_connected.values, strict=False)):
            ax2.text(count + 0.1, i, f"{int(count)}", va="center", fontweight="bold")

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "network_analysis.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created network analysis visualization")

    def create_data_coverage_summary(self):
        """Create data coverage and completeness visualization."""
        if not self.insights.get("data_coverage"):
            return

        coverage = self.insights["data_coverage"]

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

        # Data source record counts
        sources = list(coverage.keys())
        record_counts = [stats["total_records"] for stats in coverage.values()]

        bars = ax1.bar(sources, record_counts, color=plt.cm.tab10(np.linspace(0, 1, len(sources))))
        ax1.set_title("Records by Data Source", fontsize=14, fontweight="bold")
        ax1.set_ylabel("Number of Records")
        ax1.tick_params(axis="x", rotation=45)

        # Add value labels
        for bar, count in zip(bars, record_counts, strict=False):
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(record_counts) * 0.01,
                f"{count:,}",
                ha="center",
                va="bottom",
                fontweight="bold",
                fontsize=8,
            )

        # Data completeness percentages
        completeness = [stats["non_null_percentage"] for stats in coverage.values()]

        bars = ax2.barh(sources, completeness, color=plt.cm.RdYlGn(np.array(completeness) / 100))
        ax2.set_title("Data Completeness by Source", fontsize=14, fontweight="bold")
        ax2.set_xlabel("Completeness (%)")

        # Add value labels
        for i, (bar, pct) in enumerate(zip(bars, completeness, strict=False)):
            ax2.text(pct + 1, i, f"{pct:.1f}%", va="center", fontweight="bold", fontsize=8)

        # Column counts
        column_counts = [stats["columns"] for stats in coverage.values()]

        bars = ax3.bar(
            sources, column_counts, color=plt.cm.viridis(np.linspace(0, 1, len(sources)))
        )
        ax3.set_title("Columns by Data Source", fontsize=14, fontweight="bold")
        ax3.set_ylabel("Number of Columns")
        ax3.tick_params(axis="x", rotation=45)

        # Add value labels
        for bar, count in zip(bars, column_counts, strict=False):
            ax3.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                str(count),
                ha="center",
                va="bottom",
                fontweight="bold",
                fontsize=8,
            )

        # Overall summary pie chart
        total_records = sum(record_counts)
        source_percentages = [(count / total_records) * 100 for count in record_counts]

        colors = plt.cm.Set3(np.linspace(0, 1, len(sources)))
        wedges, texts, autotexts = ax4.pie(
            source_percentages, labels=sources, autopct="%1.1f%%", colors=colors, startangle=90
        )
        ax4.set_title("Data Distribution Across Sources", fontsize=14, fontweight="bold")

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "data_coverage_summary.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created data coverage summary")

    def create_cross_platform_insights_dashboard(self):
        """Create a comprehensive dashboard of cross-platform insights."""
        fig = plt.figure(figsize=(20, 12))
        gs = fig.add_gridspec(3, 4, hspace=0.3, wspace=0.3)

        # Title
        fig.suptitle(
            "Multi-Source Music Data Analysis Dashboard", fontsize=24, fontweight="bold", y=0.95
        )

        # Key metrics text box
        ax_metrics = fig.add_subplot(gs[0, :2])
        ax_metrics.axis("off")

        metrics_text = "📊 KEY INSIGHTS\n\n"

        if self.insights.get("mainstream_analysis"):
            mainstream = self.insights["mainstream_analysis"]
            metrics_text += (
                f"🎯 Overall Mainstream Score: {mainstream['average_mainstream_score']:.1f}%\n"
            )

        if self.insights.get("geographic_diversity"):
            geo = self.insights["geographic_diversity"]
            metrics_text += f"🌍 Countries Represented: {geo['unique_countries']}\n"
            if geo["top_country"]:
                metrics_text += (
                    f"📍 Top Country: {geo['top_country']} ({geo['top_country_percentage']:.1f}%)\n"
                )

        if self.insights.get("era_analysis"):
            era = self.insights["era_analysis"]
            metrics_text += f"📅 Era Span: {era['era_span_years']} years ({era['earliest_artist_year']}-{era['latest_artist_year']})\n"

        if self.insights.get("network_analysis"):
            network = self.insights["network_analysis"]
            metrics_text += (
                f"🕸️ Artist Connections: {network['total_relationships']} relationships\n"
            )

        ax_metrics.text(
            0.05,
            0.95,
            metrics_text,
            transform=ax_metrics.transAxes,
            fontsize=12,
            verticalalignment="top",
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="lightblue", alpha=0.8),
        )

        # Data sources overview
        ax_sources = fig.add_subplot(gs[0, 2:])
        ax_sources.axis("off")

        sources_text = "🔗 DATA SOURCES INTEGRATED\n\n"
        sources_text += "🎵 Spotify Personal Data\n"
        sources_text += "🌍 Last.fm Global Trends\n"
        sources_text += "📚 MusicBrainz Metadata\n"
        sources_text += "🎧 AudioDB Artist Profiles\n"
        sources_text += "📈 Spotify Global Charts\n"

        if self.insights.get("data_coverage"):
            total_records = sum(
                stats["total_records"] for stats in self.insights["data_coverage"].values()
            )
            sources_text += f"\n📊 Total Data Points: {total_records:,}"

        ax_sources.text(
            0.05,
            0.95,
            sources_text,
            transform=ax_sources.transAxes,
            fontsize=12,
            verticalalignment="top",
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="lightgreen", alpha=0.8),
        )

        # Quick visualizations in remaining space
        if self.insights.get("mainstream_analysis"):
            ax_main = fig.add_subplot(gs[1, :2])
            mainstream = self.insights["mainstream_analysis"]
            platforms = ["Spotify\nCharts", "Last.fm\nGlobal"]
            scores = [
                mainstream["spotify_charts_mainstream_percent"],
                mainstream["lastfm_mainstream_percent"],
            ]
            bars = ax_main.bar(platforms, scores, color=["#1DB954", "#D51007"], alpha=0.8)
            ax_main.set_title("Mainstream Scores", fontweight="bold")
            ax_main.set_ylabel("Score (%)")
            for bar, score in zip(bars, scores, strict=False):
                ax_main.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 1,
                    f"{score:.1f}%",
                    ha="center",
                    va="bottom",
                    fontweight="bold",
                )

        plt.tight_layout()
        save_matplotlib_figure(
            plt, self.output_dir / "multi_source_dashboard.png", dpi=300, bbox_inches="tight"
        )
        plt.close()

        print("✅ Created comprehensive dashboard")

    def create_all_visualizations(self):
        """Generate all multi-source visualizations."""
        print("🎨 Generating multi-source visualizations...")

        self.create_mainstream_comparison()
        self.create_geographic_diversity_map()
        self.create_era_timeline()
        self.create_network_analysis()
        self.create_data_coverage_summary()
        self.create_cross_platform_insights_dashboard()

        print(f"✅ Generated all visualizations in {self.output_dir}/")
