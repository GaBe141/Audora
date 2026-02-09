"""
Analytics and Machine Learning for Music Discovery
=================================================

This module contains advanced analytics, machine learning models,
and statistical analysis tools for music trend prediction.

Key Features:
    - Viral prediction using ML algorithms (80%+ accuracy)
    - Trend clustering and pattern recognition
    - Cross-platform correlation analysis
    - Time series forecasting (ARIMA, linear regression)
    - Statistical analysis and data science tools
    - Audio feature analysis and sentiment detection

Key Components:
    - advanced_analytics.py: ML-powered trend analysis
    - statistical_analysis.py: Statistical methods and analysis
    - streaming_analytics.py: Real-time streaming data analysis
    - deep_analysis.py: Deep learning models
    - simple_surprise.py: Recommendation system components
"""

__version__ = "2.0.0"

# Import key analytics classes (optional - avoid breaking submodule imports if deps fail)
try:
    from .advanced_analytics import MusicTrendAnalytics
    from .statistical_analysis import StreamingDataQualityAnalyzer, StreamingForecastingEngine

    __all__ = ["MusicTrendAnalytics", "StreamingDataQualityAnalyzer", "StreamingForecastingEngine"]
except (ImportError, AttributeError):
    __all__ = []
