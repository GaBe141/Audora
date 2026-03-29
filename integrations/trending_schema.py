"""
Comprehensive trending schema system for music analytics.
Tracks, analyzes, and predicts trending patterns across multiple dimensions.
"""

import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import numpy as np

warnings.filterwarnings("ignore")


class TrendDirection(Enum):
    """Trend direction indicators."""

    RISING = "rising"
    FALLING = "falling"
    STABLE = "stable"
    VOLATILE = "volatile"
    EMERGING = "emerging"
    VIRAL = "viral"
    DECLINING = "declining"


class TrendCategory(Enum):
    """Categories of trending analysis."""

    ARTIST = "artist"
    TRACK = "track"
    GENRE = "genre"
    ALBUM = "album"
    PLAYLIST = "playlist"
    FEATURE = "feature"
    REGION = "region"
    DEMOGRAPHIC = "demographic"


class TrendTimeframe(Enum):
    """Timeframes for trend analysis."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


@dataclass
class TrendPoint:
    """Single data point in a trend."""

    timestamp: datetime
    value: float
    metadata: dict[str, Any]
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": self.value,
            "metadata": self.metadata,
            "confidence": self.confidence,
        }


@dataclass
class TrendMetrics:
    """Metrics for a trending pattern."""

    velocity: float  # Rate of change
    acceleration: float  # Change in velocity
    momentum: float  # Sustained direction strength
    volatility: float  # Variability measure
    peak_value: float  # Highest value in timeframe
    peak_timestamp: datetime  # When peak occurred
    growth_rate: float  # Percentage growth
    trend_strength: float  # 0-1 confidence in trend direction

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "velocity": self.velocity,
            "acceleration": self.acceleration,
            "momentum": self.momentum,
            "volatility": self.volatility,
            "peak_value": self.peak_value,
            "peak_timestamp": self.peak_timestamp.isoformat(),
            "growth_rate": self.growth_rate,
            "trend_strength": self.trend_strength,
        }


@dataclass
class TrendingItem:
    """Complete trending item with all analysis."""

    item_id: str
    name: str
    category: TrendCategory
    timeframe: TrendTimeframe
    direction: TrendDirection
    current_value: float
    previous_value: float
    data_points: list[TrendPoint]
    metrics: TrendMetrics
    rank: int | None = None
    rank_change: int | None = None
    tags: list[str] | None = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "item_id": self.item_id,
            "name": self.name,
            "category": self.category.value,
            "timeframe": self.timeframe.value,
            "direction": self.direction.value,
            "current_value": self.current_value,
            "previous_value": self.previous_value,
            "data_points": [point.to_dict() for point in self.data_points],
            "metrics": self.metrics.to_dict(),
            "rank": self.rank,
            "rank_change": self.rank_change,
            "tags": self.tags,
        }


class TrendAnalyzer:
    """Core trend analysis engine."""

    def __init__(self, min_data_points: int = 5, confidence_threshold: float = 0.7):
        self.min_data_points = min_data_points
        self.confidence_threshold = confidence_threshold

        # Trend detection parameters
        self.trend_thresholds = {
            "stable": 0.05,  # Less than 5% change
            "rising": 0.15,  # 15%+ growth
            "falling": -0.15,  # 15%+ decline
            "viral": 0.50,  # 50%+ explosive growth
            "volatile": 0.30,  # High variance threshold
        }

    def analyze_time_series(
        self, data_points: list[TrendPoint]
    ) -> tuple[TrendDirection, TrendMetrics]:
        """Analyze a time series to determine trend direction and metrics."""
        if len(data_points) < self.min_data_points:
            raise ValueError(f"Need at least {self.min_data_points} data points for analysis")

        # Sort by timestamp
        sorted_points = sorted(data_points, key=lambda x: x.timestamp)
        values = np.array([point.value for point in sorted_points])
        timestamps = [point.timestamp for point in sorted_points]

        # Calculate basic metrics
        velocity = self._calculate_velocity(values)
        acceleration = self._calculate_acceleration(values)
        momentum = self._calculate_momentum(values)
        volatility = self._calculate_volatility(values)

        # Find peak
        peak_idx = np.argmax(values)
        peak_value = values[peak_idx]
        peak_timestamp = timestamps[peak_idx]

        # Calculate growth rate
        if len(values) >= 2:
            growth_rate = ((values[-1] - values[0]) / values[0]) * 100 if values[0] != 0 else 0
        else:
            growth_rate = 0

        # Determine trend strength
        trend_strength = self._calculate_trend_strength(values)

        # Create metrics object
        metrics = TrendMetrics(
            velocity=velocity,
            acceleration=acceleration,
            momentum=momentum,
            volatility=volatility,
            peak_value=peak_value,
            peak_timestamp=peak_timestamp,
            growth_rate=growth_rate,
            trend_strength=trend_strength,
        )

        # Determine trend direction
        direction = self._classify_trend_direction(metrics)

        return direction, metrics

    def _calculate_velocity(self, values: np.ndarray) -> float:
        """Calculate rate of change (velocity)."""
        if len(values) < 2:
            return 0.0

        # Calculate differences between consecutive points
        diffs = np.diff(values)
        return float(np.mean(diffs))

    def _calculate_acceleration(self, values: np.ndarray) -> float:
        """Calculate change in velocity (acceleration)."""
        if len(values) < 3:
            return 0.0

        # Calculate second derivative
        second_diffs = np.diff(values, n=2)
        return float(np.mean(second_diffs))

    def _calculate_momentum(self, values: np.ndarray) -> float:
        """Calculate sustained direction strength."""
        if len(values) < 2:
            return 0.0

        diffs = np.diff(values)
        # Count consecutive changes in same direction
        positive_runs = 0
        negative_runs = 0
        current_run = 0
        last_sign = 0

        for diff in diffs:
            sign = 1 if diff > 0 else -1 if diff < 0 else 0

            if sign == last_sign and sign != 0:
                current_run += 1
            else:
                if last_sign > 0:
                    positive_runs = max(positive_runs, current_run)
                elif last_sign < 0:
                    negative_runs = max(negative_runs, current_run)
                current_run = 1
                last_sign = sign

        # Update final run
        if last_sign > 0:
            positive_runs = max(positive_runs, current_run)
        elif last_sign < 0:
            negative_runs = max(negative_runs, current_run)

        # Return normalized momentum (0-1)
        max_run = max(positive_runs, negative_runs)
        return min(max_run / len(diffs), 1.0)

    def _calculate_volatility(self, values: np.ndarray) -> float:
        """Calculate volatility (normalized standard deviation)."""
        if len(values) < 2:
            return 0.0

        mean_val = np.mean(values)
        if mean_val == 0:
            return 0.0

        std_val = np.std(values)
        return std_val / mean_val  # Coefficient of variation

    def _calculate_trend_strength(self, values: np.ndarray) -> float:
        """Calculate confidence in trend direction (0-1)."""
        if len(values) < 2:
            return 0.0

        # Linear regression to find trend line
        x = np.arange(len(values))
        y = values

        # Calculate correlation coefficient
        correlation = np.corrcoef(x, y)[0, 1]

        # Return absolute correlation as trend strength
        return abs(correlation) if not np.isnan(correlation) else 0.0

    def _classify_trend_direction(self, metrics: TrendMetrics) -> TrendDirection:
        """Classify trend direction based on metrics."""
        growth_rate = metrics.growth_rate
        volatility = metrics.volatility
        trend_strength = metrics.trend_strength

        # Check for viral growth
        if growth_rate >= self.trend_thresholds["viral"] * 100:
            return TrendDirection.VIRAL

        # Check for high volatility
        if volatility >= self.trend_thresholds["volatile"]:
            return TrendDirection.VOLATILE

        # Check trend strength
        if trend_strength < self.confidence_threshold:
            return TrendDirection.STABLE

        # Classify based on growth rate
        if growth_rate >= self.trend_thresholds["rising"] * 100:
            return TrendDirection.RISING
        elif growth_rate <= self.trend_thresholds["falling"] * 100:
            return TrendDirection.FALLING
        else:
            return TrendDirection.STABLE


class TrendingSchema:
    """Complete trending schema system."""

    def __init__(self, data_retention_days: int = 365):
        self.data_retention_days = data_retention_days
        self.analyzer = TrendAnalyzer()

        # Storage for trending data
        self.trending_items: dict[str, TrendingItem] = {}
        self.trending_history: dict[str, list[TrendingItem]] = {}

        # Configuration
        self.timeframe_configs = {
            TrendTimeframe.HOURLY: {"window_size": 24, "min_points": 5},
            TrendTimeframe.DAILY: {"window_size": 30, "min_points": 7},
            TrendTimeframe.WEEKLY: {"window_size": 12, "min_points": 4},
            TrendTimeframe.MONTHLY: {"window_size": 12, "min_points": 3},
            TrendTimeframe.QUARTERLY: {"window_size": 8, "min_points": 2},
            TrendTimeframe.YEARLY: {"window_size": 5, "min_points": 2},
        }

    def add_data_point(
        self,
        item_id: str,
        name: str,
        category: TrendCategory,
        value: float,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a new data point for trending analysis."""
        if timestamp is None:
            timestamp = datetime.now()

        if metadata is None:
            metadata = {}

        data_point = TrendPoint(timestamp=timestamp, value=value, metadata=metadata)

        # Initialize or update trending item
        if item_id not in self.trending_items:
            self.trending_items[item_id] = TrendingItem(
                item_id=item_id,
                name=name,
                category=category,
                timeframe=TrendTimeframe.DAILY,
                direction=TrendDirection.STABLE,
                current_value=value,
                previous_value=value,
                data_points=[data_point],
                metrics=TrendMetrics(0, 0, 0, 0, value, timestamp, 0, 0),
            )
        else:
            item = self.trending_items[item_id]
            item.previous_value = item.current_value
            item.current_value = value
            item.data_points.append(data_point)

            # Maintain data retention
            cutoff_date = datetime.now() - timedelta(days=self.data_retention_days)
            item.data_points = [
                point for point in item.data_points if point.timestamp >= cutoff_date
            ]

    def analyze_trending_item(
        self, item_id: str, timeframe: TrendTimeframe = TrendTimeframe.DAILY
    ) -> TrendingItem | None:
        """Analyze trending patterns for a specific item."""
        if item_id not in self.trending_items:
            return None

        item = self.trending_items[item_id]
        config = self.timeframe_configs[timeframe]

        # Filter data points for timeframe
        now = datetime.now()
        if timeframe == TrendTimeframe.HOURLY:
            cutoff = now - timedelta(hours=config["window_size"])
        elif timeframe == TrendTimeframe.DAILY:
            cutoff = now - timedelta(days=config["window_size"])
        elif timeframe == TrendTimeframe.WEEKLY:
            cutoff = now - timedelta(weeks=config["window_size"])
        elif timeframe == TrendTimeframe.MONTHLY:
            cutoff = now - timedelta(days=config["window_size"] * 30)
        elif timeframe == TrendTimeframe.QUARTERLY:
            cutoff = now - timedelta(days=config["window_size"] * 90)
        else:  # YEARLY
            cutoff = now - timedelta(days=config["window_size"] * 365)

        filtered_points = [point for point in item.data_points if point.timestamp >= cutoff]

        if len(filtered_points) < config["min_points"]:
            return None

        try:
            # Analyze trend
            direction, metrics = self.analyzer.analyze_time_series(filtered_points)

            # Update item
            updated_item = TrendingItem(
                item_id=item.item_id,
                name=item.name,
                category=item.category,
                timeframe=timeframe,
                direction=direction,
                current_value=item.current_value,
                previous_value=item.previous_value,
                data_points=filtered_points,
                metrics=metrics,
                tags=item.tags.copy() if item.tags is not None else [],
            )

            return updated_item

        except ValueError:
            return None

    def get_trending_by_category(
        self,
        category: TrendCategory,
        timeframe: TrendTimeframe = TrendTimeframe.DAILY,
        limit: int = 20,
    ) -> list[TrendingItem]:
        """Get trending items for a specific category."""
        trending_items = []

        for item_id in self.trending_items:
            if self.trending_items[item_id].category == category:
                analyzed_item = self.analyze_trending_item(item_id, timeframe)
                if analyzed_item:
                    trending_items.append(analyzed_item)

        # Sort by trend strength and growth rate
        trending_items.sort(
            key=lambda x: (x.metrics.trend_strength * abs(x.metrics.growth_rate)), reverse=True
        )

        # Add rankings
        for i, item in enumerate(trending_items[:limit]):
            item.rank = i + 1

        return trending_items[:limit]

    def get_viral_content(
        self, timeframe: TrendTimeframe = TrendTimeframe.DAILY
    ) -> list[TrendingItem]:
        """Get content that's going viral."""
        viral_items = []

        for item_id in self.trending_items:
            analyzed_item = self.analyze_trending_item(item_id, timeframe)
            if analyzed_item and analyzed_item.direction == TrendDirection.VIRAL:
                viral_items.append(analyzed_item)

        # Sort by growth rate
        viral_items.sort(key=lambda x: x.metrics.growth_rate, reverse=True)

        return viral_items

    def get_emerging_trends(
        self, timeframe: TrendTimeframe = TrendTimeframe.WEEKLY
    ) -> list[TrendingItem]:
        """Get emerging trends (consistent growth from low base)."""
        emerging_items = []

        for item_id in self.trending_items:
            analyzed_item = self.analyze_trending_item(item_id, timeframe)
            if analyzed_item:
                # Check for emerging pattern
                metrics = analyzed_item.metrics
                if (
                    metrics.growth_rate > 20  # Good growth
                    and metrics.trend_strength > 0.7  # Consistent
                    and metrics.momentum > 0.5  # Sustained
                    and analyzed_item.data_points[0].value < 100
                ):  # Low initial value
                    analyzed_item.direction = TrendDirection.EMERGING
                    emerging_items.append(analyzed_item)

        # Sort by momentum and trend strength
        emerging_items.sort(
            key=lambda x: x.metrics.momentum * x.metrics.trend_strength, reverse=True
        )

        return emerging_items

    def predict_trend_continuation(
        self, item_id: str, periods_ahead: int = 7
    ) -> dict[str, Any] | None:
        """Predict if a trend will continue."""
        analyzed_item = self.analyze_trending_item(item_id)
        if not analyzed_item:
            return None

        metrics = analyzed_item.metrics

        # Simple linear projection
        values = [point.value for point in analyzed_item.data_points]
        if len(values) < 3:
            return None

        # Calculate trend line
        x = np.arange(len(values))
        z = np.polyfit(x, values, 1)
        slope = z[0]
        intercept = z[1]

        # Project forward
        future_x = np.arange(len(values), len(values) + periods_ahead)
        predictions = slope * future_x + intercept

        # Calculate confidence based on historical trend strength
        confidence = metrics.trend_strength * (1 - metrics.volatility)

        return {
            "item_id": item_id,
            "current_direction": analyzed_item.direction.value,
            "predictions": predictions.tolist(),
            "confidence": confidence,
            "trend_strength": metrics.trend_strength,
            "expected_direction": "rising" if slope > 0 else "falling",
            "volatility_warning": metrics.volatility > 0.3,
        }

    def export_trending_snapshot(self, filepath: str | None = None) -> dict[str, Any]:
        """Export current trending analysis snapshot.

        For security, restrict custom file paths to project-relative locations
        and reject absolute / parent-traversal paths.
        """
        if filepath is None:
            filepath = f"data/trending_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        else:
            from pathlib import Path

            requested = Path(filepath)
            if requested.is_absolute():
                raise ValueError("Absolute snapshot paths are not allowed")
            if ".." in requested.parts:
                raise ValueError("Snapshot path cannot traverse parent directories")

        snapshot: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "total_items": len(self.trending_items),
            "categories": {},
            "trending_summary": {
                "viral_count": 0,
                "rising_count": 0,
                "falling_count": 0,
                "stable_count": 0,
                "emerging_count": 0,
                "declining_count": 0,
                "volatile_count": 0,
            },
        }

        # Analyze by category
        for category in TrendCategory:
            trending_items = self.get_trending_by_category(category)
            category_data: dict[str, Any] = {
                "total_items": len(trending_items),
                "top_trending": [item.to_dict() for item in trending_items[:5]],
                "directions": {},
            }
            snapshot["categories"][category.value] = category_data

            # Count directions
            directions_dict: dict[str, int] = category_data["directions"]
            trending_summary: dict[str, int] = snapshot["trending_summary"]
            for direction in TrendDirection:
                count = len([item for item in trending_items if item.direction == direction])
                directions_dict[direction.value] = count
                trending_summary[f"{direction.value}_count"] += count

        # Get viral content
        viral_content = self.get_viral_content()
        snapshot["viral_content"] = [item.to_dict() for item in viral_content]

        # Get emerging trends
        emerging_trends = self.get_emerging_trends()
        snapshot["emerging_trends"] = [item.to_dict() for item in emerging_trends]

        # Save to file using centralized utility
        from core.utils import write_json

        write_json(filepath, snapshot)
        return snapshot


def create_sample_trending_data() -> TrendingSchema:
    """Create sample trending data for testing."""
    schema = TrendingSchema()

    # Sample artists with different trending patterns
    artists_data: list[dict[str, Any]] = [
        # Viral artist
        {
            "id": "artist_1",
            "name": "Viral Artist",
            "category": TrendCategory.ARTIST,
            "pattern": "viral",
            "values": [100, 150, 300, 800, 1500, 2200, 2800, 3000, 2900, 2800],
        },
        # Steady rising artist
        {
            "id": "artist_2",
            "name": "Rising Star",
            "category": TrendCategory.ARTIST,
            "pattern": "rising",
            "values": [200, 230, 270, 320, 380, 450, 530, 620, 720, 830],
        },
        # Declining artist
        {
            "id": "artist_3",
            "name": "Fading Star",
            "category": TrendCategory.ARTIST,
            "pattern": "falling",
            "values": [1000, 950, 880, 800, 720, 650, 580, 520, 470, 420],
        },
        # Volatile artist
        {
            "id": "artist_4",
            "name": "Unpredictable Artist",
            "category": TrendCategory.ARTIST,
            "pattern": "volatile",
            "values": [300, 500, 200, 700, 150, 600, 250, 800, 100, 650],
        },
    ]

    # Add sample data points
    base_time = datetime.now() - timedelta(days=10)

    for artist in artists_data:
        artist_values = artist["values"]
        assert isinstance(artist_values, list)
        for i, value in enumerate(artist_values):
            timestamp = base_time + timedelta(days=i)
            schema.add_data_point(
                item_id=str(artist["id"]),
                name=str(artist["name"]),
                category=artist["category"],
                value=float(value),
                timestamp=timestamp,
                metadata={"pattern": artist["pattern"]},
            )

    return schema


if __name__ == "__main__":
    print("🔥 Testing Trending Schema System")
    print("=" * 50)

    # Create sample data
    schema = create_sample_trending_data()

    print(f"✅ Created trending schema with {len(schema.trending_items)} items")

    # Test category analysis
    trending_artists = schema.get_trending_by_category(TrendCategory.ARTIST)
    print("\n📈 Top Trending Artists:")
    for item in trending_artists[:3]:
        direction_emoji = {
            TrendDirection.VIRAL: "🚀",
            TrendDirection.RISING: "📈",
            TrendDirection.FALLING: "📉",
            TrendDirection.VOLATILE: "⚡",
        }.get(item.direction, "📊")

        print(f"   {direction_emoji} {item.name}: {item.direction.value}")
        print(f"      Growth: {item.metrics.growth_rate:.1f}%")
        print(f"      Trend Strength: {item.metrics.trend_strength:.2f}")

    # Test viral detection
    viral_items = schema.get_viral_content()
    print(f"\n🚀 Viral Content ({len(viral_items)} items):")
    for item in viral_items:
        print(f"   🔥 {item.name}: +{item.metrics.growth_rate:.0f}% growth")

    # Test emerging trends
    emerging_items = schema.get_emerging_trends()
    print(f"\n🌱 Emerging Trends ({len(emerging_items)} items):")
    for item in emerging_items:
        print(f"   📊 {item.name}: {item.metrics.momentum:.2f} momentum")

    # Test prediction
    if trending_artists:
        prediction = schema.predict_trend_continuation(trending_artists[0].item_id)
        if prediction:
            print(f"\n🔮 Prediction for {trending_artists[0].name}:")
            print(f"   Direction: {prediction['expected_direction']}")
            print(f"   Confidence: {prediction['confidence']:.2f}")
            print(f"   Next 3 values: {[round(v) for v in prediction['predictions'][:3]]}")

    # Export snapshot
    snapshot = schema.export_trending_snapshot()
    print("\n💾 Exported trending snapshot")
    print(f"   Total items: {snapshot['total_items']}")
    print(f"   Viral items: {len(snapshot['viral_content'])}")
    print(f"   Emerging trends: {len(snapshot['emerging_trends'])}")

    print("\n🎯 Trending schema system ready!")
