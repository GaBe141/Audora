"""Tests for analytics enhanced_viral_prediction (momentum, acceleration, predict_viral_potential, batch_predict)."""

from datetime import datetime, timedelta

from analytics.enhanced_viral_prediction import EnhancedViralPredictor, ViralMetrics


class TestCalculateMomentum:
    """Tests for calculate_momentum."""

    def test_increasing_values_positive_momentum(self):
        predictor = EnhancedViralPredictor()
        base = datetime(2024, 1, 1)
        values = [10.0, 20.0, 30.0, 40.0, 50.0]
        timestamps = [base + timedelta(days=i) for i in range(len(values))]
        momentum = predictor.calculate_momentum(values, timestamps)
        assert momentum >= 0
        assert momentum <= 100

    def test_decreasing_values_negative_or_low_momentum(self):
        predictor = EnhancedViralPredictor()
        base = datetime(2024, 1, 1)
        values = [50.0, 40.0, 30.0, 20.0, 10.0]
        timestamps = [base + timedelta(days=i) for i in range(len(values))]
        momentum = predictor.calculate_momentum(values, timestamps)
        assert momentum <= 100

    def test_less_than_two_values_returns_zero(self):
        predictor = EnhancedViralPredictor()
        momentum = predictor.calculate_momentum([1.0], [datetime(2024, 1, 1)])
        assert momentum == 0.0


class TestCalculateAcceleration:
    """Tests for calculate_acceleration."""

    def test_returns_numeric_in_range(self):
        predictor = EnhancedViralPredictor()
        base = datetime(2024, 1, 1)
        values = [10.0, 20.0, 35.0, 55.0]
        timestamps = [base + timedelta(days=i) for i in range(len(values))]
        accel = predictor.calculate_acceleration(values, timestamps)
        assert -100 <= accel <= 100

    def test_less_than_three_values_returns_zero(self):
        predictor = EnhancedViralPredictor()
        accel = predictor.calculate_acceleration(
            [1.0, 2.0],
            [datetime(2024, 1, 1), datetime(2024, 1, 2)],
        )
        assert accel == 0.0


class TestPredictViralPotential:
    """Tests for predict_viral_potential - minimal track_data."""

    def test_returns_viral_metrics_with_required_attributes(self):
        predictor = EnhancedViralPredictor()
        track_data = {
            "track_name": "Test Song",
            "platform_scores": {"spotify": 85, "tiktok": 92, "youtube": 78},
            "social_signals": {"mentions": 15000, "shares": 3500, "comments": 850},
            "audio_features": {"danceability": 0.85, "energy": 0.78, "valence": 0.72},
        }
        metrics = predictor.predict_viral_potential(track_data)
        assert isinstance(metrics, ViralMetrics)
        assert hasattr(metrics, "viral_score")
        assert hasattr(metrics, "confidence")
        assert hasattr(metrics, "recommendation")
        assert 0 <= metrics.viral_score <= 100
        assert 0 <= metrics.confidence <= 1
        assert len(metrics.recommendation) > 0

    def test_minimal_track_data_succeeds(self):
        predictor = EnhancedViralPredictor()
        track_data = {"track_name": "Minimal", "platform_scores": {}}
        metrics = predictor.predict_viral_potential(track_data)
        assert metrics.viral_score >= 0
        assert metrics.confidence >= 0


class TestBatchPredict:
    """Tests for batch_predict."""

    def test_batch_predict_returns_same_length(self):
        predictor = EnhancedViralPredictor()
        tracks = [
            {"track_name": "A", "platform_scores": {"spotify": 70}},
            {"track_name": "B", "platform_scores": {"tiktok": 80}},
        ]
        results = predictor.batch_predict(tracks)
        assert len(results) == 2
        for _td, metrics in results:
            assert isinstance(metrics, ViralMetrics)

    def test_batch_predict_sorted_by_viral_score_desc(self):
        predictor = EnhancedViralPredictor()
        tracks = [
            {"track_name": "Low", "platform_scores": {"spotify": 30}},
            {"track_name": "High", "platform_scores": {"spotify": 90}},
        ]
        results = predictor.batch_predict(tracks)
        assert results[0][1].viral_score >= results[1][1].viral_score
