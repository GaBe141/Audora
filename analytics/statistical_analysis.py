"""Statistical analysis and forecasting module for music streaming data quality improvement."""

import json
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

try:
    from statsmodels.stats.diagnostic import acorr_ljungbox
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.statespace.sarimax import SARIMAX
    from statsmodels.tsa.stattools import adfuller, kpss

    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest, RandomForestRegressor
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    from sklearn.model_selection import train_test_split

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    from darts import TimeSeries
    from darts.metrics import mae, mape, rmse, smape
    from darts.models import AutoARIMA, ExponentialSmoothing, LinearRegressionModel, Theta

    DARTS_AVAILABLE = True
except ImportError:
    DARTS_AVAILABLE = False


class StreamingDataQualityAnalyzer:
    """Advanced statistical analysis for streaming data quality improvement."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.models: dict[str, Any] = {}
        self.forecasts: dict[str, Any] = {}
        self.quality_metrics: dict[str, Any] = {}
        self.anomaly_detectors: dict[str, Any] = {}

        # Check available libraries
        self.available_libs = {
            "statsmodels": STATSMODELS_AVAILABLE,
            "sklearn": SKLEARN_AVAILABLE,
            "darts": DARTS_AVAILABLE,
        }

        if verbose:
            self._log_library_status()

    def _log_library_status(self):
        """Log the status of statistical libraries."""
        print("📊 Statistical Analysis Libraries Status:")
        for lib, available in self.available_libs.items():
            status = "✅ Available" if available else "❌ Missing"
            print(f"   {lib}: {status}")
        print()

    def analyze_data_quality(
        self, data: pd.DataFrame, timestamp_col: str, value_cols: list[str]
    ) -> dict[str, Any]:
        """Comprehensive data quality analysis."""
        print("🔍 Analyzing data quality...")

        quality_report = {
            "timestamp": datetime.now().isoformat(),
            "data_shape": data.shape,
            "columns_analyzed": value_cols,
            "quality_issues": {},
            "recommendations": [],
        }

        # Basic data quality checks
        quality_report["basic_stats"] = {
            "total_rows": len(data),
            "missing_values": data[value_cols].isnull().sum().to_dict(),
            "duplicate_rows": data.duplicated().sum(),
            "zero_values": (data[value_cols] == 0).sum().to_dict(),
        }

        # Temporal consistency checks
        if timestamp_col in data.columns:
            quality_report["temporal_analysis"] = self._analyze_temporal_consistency(
                data, timestamp_col
            )

        # Statistical outlier detection
        if SKLEARN_AVAILABLE:
            quality_report["outlier_analysis"] = self._detect_statistical_outliers(data, value_cols)

        # Time series specific quality checks
        for col in value_cols:
            if col in data.columns:
                quality_report["quality_issues"][col] = self._analyze_column_quality(
                    data, col, timestamp_col
                )

        # Generate recommendations
        quality_report["recommendations"] = self._generate_quality_recommendations(quality_report)

        self.quality_metrics = quality_report
        return quality_report

    def _analyze_temporal_consistency(
        self, data: pd.DataFrame, timestamp_col: str
    ) -> dict[str, Any]:
        """Analyze temporal consistency in the data."""
        temporal_analysis = {}

        if timestamp_col not in data.columns:
            return {"error": f"Timestamp column {timestamp_col} not found"}

        # Convert to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(data[timestamp_col]):
            try:
                timestamps = pd.to_datetime(data[timestamp_col])
            except Exception:
                timestamps = data[timestamp_col]
        else:
            timestamps = data[timestamp_col]

        # Check for gaps
        if len(timestamps) > 1:
            time_diffs = timestamps.diff().dropna()
            temporal_analysis.update(
                {
                    "date_range": {
                        "start": timestamps.min().isoformat(),
                        "end": timestamps.max().isoformat(),
                        "span_days": (timestamps.max() - timestamps.min()).days,
                    },
                    "frequency_analysis": {
                        "median_interval": time_diffs.median().total_seconds(),
                        "std_interval": time_diffs.std().total_seconds(),
                        "irregular_intervals": (time_diffs.std() / time_diffs.median()),
                    },
                    "gaps_detected": len(time_diffs[time_diffs > time_diffs.median() * 2]),
                }
            )

        return temporal_analysis

    def _detect_statistical_outliers(
        self, data: pd.DataFrame, value_cols: list[str]
    ) -> dict[str, Any]:
        """Detect outliers using multiple statistical methods."""
        outlier_analysis = {}

        for col in value_cols:
            if col not in data.columns:
                continue

            col_data = data[col].dropna()
            if len(col_data) == 0:
                continue

            outliers = {}

            # IQR method
            Q1 = col_data.quantile(0.25)
            Q3 = col_data.quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR

            iqr_outliers = col_data[(col_data < lower_bound) | (col_data > upper_bound)]
            outliers["iqr"] = {
                "count": len(iqr_outliers),
                "percentage": len(iqr_outliers) / len(col_data) * 100,
                "bounds": {"lower": lower_bound, "upper": upper_bound},
            }

            # Z-score method
            z_scores = np.abs((col_data - col_data.mean()) / col_data.std())
            z_outliers = col_data[z_scores > 3]
            outliers["zscore"] = {
                "count": len(z_outliers),
                "percentage": len(z_outliers) / len(col_data) * 100,
                "threshold": 3,
            }

            # Isolation Forest (if sklearn available)
            if SKLEARN_AVAILABLE and len(col_data) > 10:
                try:
                    iso_forest = IsolationForest(contamination=0.1, random_state=42)
                    outlier_labels = iso_forest.fit_predict(col_data.values.reshape(-1, 1))
                    iso_outliers = col_data[outlier_labels == -1]
                    outliers["isolation_forest"] = {
                        "count": len(iso_outliers),
                        "percentage": len(iso_outliers) / len(col_data) * 100,
                    }
                except Exception:
                    outliers["isolation_forest"] = {"error": "Failed to run Isolation Forest"}

            outlier_analysis[col] = outliers

        return outlier_analysis

    def _analyze_column_quality(
        self, data: pd.DataFrame, col: str, timestamp_col: str
    ) -> dict[str, Any]:
        """Analyze quality metrics for a specific column."""
        col_analysis = {}

        if col not in data.columns:
            return {"error": f"Column {col} not found"}

        col_data = data[col].dropna()

        # Basic statistics
        col_analysis["basic_stats"] = {
            "count": len(col_data),
            "mean": float(col_data.mean()) if len(col_data) > 0 else None,
            "std": float(col_data.std()) if len(col_data) > 0 else None,
            "min": float(col_data.min()) if len(col_data) > 0 else None,
            "max": float(col_data.max()) if len(col_data) > 0 else None,
            "skewness": float(col_data.skew()) if len(col_data) > 0 else None,
            "kurtosis": float(col_data.kurtosis()) if len(col_data) > 0 else None,
        }

        # Stationarity tests (if data is time series)
        if STATSMODELS_AVAILABLE and len(col_data) > 12:
            try:
                adf_result = adfuller(col_data)
                col_analysis["stationarity"] = {
                    "adf_statistic": adf_result[0],
                    "adf_pvalue": adf_result[1],
                    "is_stationary_adf": adf_result[1] < 0.05,
                }

                # KPSS test
                kpss_result = kpss(col_data)
                col_analysis["stationarity"].update(
                    {
                        "kpss_statistic": kpss_result[0],
                        "kpss_pvalue": kpss_result[1],
                        "is_stationary_kpss": kpss_result[1] > 0.05,
                    }
                )
            except Exception:
                col_analysis["stationarity"] = {"error": "Stationarity tests failed"}

        return col_analysis

    def _generate_quality_recommendations(self, quality_report: dict[str, Any]) -> list[str]:
        """Generate data quality improvement recommendations."""
        recommendations = []

        # Missing values recommendations
        missing_values = quality_report["basic_stats"]["missing_values"]
        for col, missing_count in missing_values.items():
            if missing_count > 0:
                missing_pct = (missing_count / quality_report["basic_stats"]["total_rows"]) * 100
                if missing_pct > 20:
                    recommendations.append(
                        f"High missing values in {col} ({missing_pct:.1f}%). Consider imputation or removal."
                    )
                elif missing_pct > 5:
                    recommendations.append(
                        f"Moderate missing values in {col} ({missing_pct:.1f}%). Apply forward fill or interpolation."
                    )

        # Outlier recommendations
        if "outlier_analysis" in quality_report:
            for col, outliers in quality_report["outlier_analysis"].items():
                if "iqr" in outliers and outliers["iqr"]["percentage"] > 10:
                    recommendations.append(
                        f"High outlier percentage in {col} ({outliers['iqr']['percentage']:.1f}%). Consider outlier treatment."
                    )

        # Temporal consistency recommendations
        if "temporal_analysis" in quality_report:
            temporal = quality_report["temporal_analysis"]
            if "gaps_detected" in temporal and temporal["gaps_detected"] > 0:
                recommendations.append(
                    f"Detected {temporal['gaps_detected']} temporal gaps. Consider interpolation or gap filling."
                )

        return recommendations


class StreamingForecastingEngine:
    """Multi-model forecasting engine for streaming data prediction."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.models: dict[str, Any] = {}
        self.forecasts: dict[str, Any] = {}
        self.model_performance: dict[str, Any] = {}

        # Available model types
        self.available_models = {
            "arima": STATSMODELS_AVAILABLE,
            "sarima": STATSMODELS_AVAILABLE,
            "darts_arima": DARTS_AVAILABLE,
            "prophet": DARTS_AVAILABLE,
            "exponential_smoothing": DARTS_AVAILABLE,
            "theta": DARTS_AVAILABLE,
            "auto_arima": DARTS_AVAILABLE,
            "random_forest": SKLEARN_AVAILABLE,
            "linear_regression": SKLEARN_AVAILABLE or DARTS_AVAILABLE,
        }

        if verbose:
            self._log_model_availability()

    def _log_model_availability(self):
        """Log available forecasting models."""
        print("📈 Available Forecasting Models:")
        for model, available in self.available_models.items():
            status = "✅" if available else "❌"
            print(f"   {status} {model}")
        print()

    def prepare_time_series(
        self, data: pd.DataFrame, timestamp_col: str, value_col: str, freq: str = "D"
    ) -> tuple[pd.Series, dict[str, Any]]:
        """Prepare time series data for forecasting."""
        print(f"🔧 Preparing time series for {value_col}...")

        # Convert timestamp column
        if not pd.api.types.is_datetime64_any_dtype(data[timestamp_col]):
            data[timestamp_col] = pd.to_datetime(data[timestamp_col])

        # Sort by timestamp
        data_sorted = data.sort_values(timestamp_col)

        # Create time series
        ts = data_sorted.set_index(timestamp_col)[value_col]

        # Remove duplicates (keep last)
        ts = ts[~ts.index.duplicated(keep="last")]

        # Resample to consistent frequency
        ts_resampled = ts.resample(freq).mean()

        # Handle missing values
        ts_filled = ts_resampled.interpolate(method="linear")

        # Preparation metadata
        prep_info = {
            "original_length": len(ts),
            "resampled_length": len(ts_resampled),
            "filled_length": len(ts_filled),
            "missing_filled": ts_resampled.isna().sum(),
            "frequency": freq,
            "date_range": {
                "start": ts_filled.index.min().isoformat(),
                "end": ts_filled.index.max().isoformat(),
            },
        }

        return ts_filled, prep_info

    def fit_arima_model(
        self, ts: pd.Series, order: tuple[int, int, int] = (1, 1, 1)
    ) -> dict[str, Any]:
        """Fit ARIMA model using statsmodels."""
        if not STATSMODELS_AVAILABLE:
            return {"error": "statsmodels not available"}

        try:
            model = ARIMA(ts, order=order)
            fitted_model = model.fit()

            # Model diagnostics
            diagnostics = {
                "aic": fitted_model.aic,
                "bic": fitted_model.bic,
                "log_likelihood": fitted_model.llf,
                "params": fitted_model.params.to_dict(),
                "residuals_mean": fitted_model.resid.mean(),
                "residuals_std": fitted_model.resid.std(),
            }

            # Ljung-Box test for residuals
            try:
                lb_test = acorr_ljungbox(fitted_model.resid, lags=10, return_df=True)
                diagnostics["ljung_box_pvalue"] = lb_test["lb_pvalue"].mean()
            except Exception:
                pass

            self.models[f"arima_{order}"] = fitted_model
            return {
                "model_type": "ARIMA",
                "order": order,
                "diagnostics": diagnostics,
                "success": True,
            }

        except Exception as e:
            return {"error": str(e), "success": False}

    def fit_sarima_model(
        self,
        ts: pd.Series,
        order: tuple[int, int, int] = (1, 1, 1),
        seasonal_order: tuple[int, int, int, int] = (1, 1, 1, 12),
    ) -> dict[str, Any]:
        """Fit SARIMA model using statsmodels."""
        if not STATSMODELS_AVAILABLE:
            return {"error": "statsmodels not available"}

        try:
            model = SARIMAX(ts, order=order, seasonal_order=seasonal_order)
            fitted_model = model.fit()

            diagnostics = {
                "aic": fitted_model.aic,
                "bic": fitted_model.bic,
                "log_likelihood": fitted_model.llf,
                "params": fitted_model.params.to_dict(),
                "residuals_mean": fitted_model.resid.mean(),
                "residuals_std": fitted_model.resid.std(),
            }

            self.models[f"sarima_{order}_{seasonal_order}"] = fitted_model
            return {
                "model_type": "SARIMA",
                "order": order,
                "seasonal_order": seasonal_order,
                "diagnostics": diagnostics,
                "success": True,
            }

        except Exception as e:
            return {"error": str(e), "success": False}

    def fit_darts_models(self, ts: pd.Series) -> dict[str, Any]:
        """Fit multiple models using Darts library."""
        if not DARTS_AVAILABLE:
            return {"error": "Darts not available"}

        results = {}

        try:
            # Convert to Darts TimeSeries
            darts_ts = TimeSeries.from_series(ts)

            # Split for validation
            train_size = int(0.8 * len(darts_ts))
            train, val = darts_ts[:train_size], darts_ts[train_size:]

            # Models to try
            models_to_fit = [
                ("auto_arima", AutoARIMA()),
                ("exponential_smoothing", ExponentialSmoothing()),
                ("theta", Theta()),
                ("linear_regression", LinearRegressionModel(lags=5)),
            ]

            for model_name, model in models_to_fit:
                try:
                    print(f"   Fitting {model_name}...")
                    model.fit(train)

                    # Make predictions on validation set
                    pred = model.predict(len(val))

                    # Calculate metrics
                    metrics = {
                        "mae": mae(val, pred),
                        "rmse": rmse(val, pred),
                        "mape": mape(val, pred),
                        "smape": smape(val, pred),
                    }

                    self.models[f"darts_{model_name}"] = model
                    results[model_name] = {"metrics": metrics, "success": True}

                except Exception as e:
                    results[model_name] = {"error": str(e), "success": False}

        except Exception as e:
            return {"error": str(e)}

        return results

    def fit_sklearn_models(self, ts: pd.Series, lags: int = 5) -> dict[str, Any]:
        """Fit sklearn-based models for time series forecasting."""
        if not SKLEARN_AVAILABLE:
            return {"error": "sklearn not available"}

        results = {}

        try:
            # Create lagged features
            X, y = self._create_lagged_features(ts, lags)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, shuffle=False, random_state=42
            )

            # Models to try
            models_to_fit = [
                ("random_forest", RandomForestRegressor(n_estimators=100, random_state=42)),
            ]

            for model_name, model in models_to_fit:
                try:
                    print(f"   Fitting {model_name}...")
                    model.fit(X_train, y_train)

                    # Predictions
                    y_pred = model.predict(X_test)

                    # Metrics
                    metrics = {
                        "mae": mean_absolute_error(y_test, y_pred),
                        "rmse": np.sqrt(mean_squared_error(y_test, y_pred)),
                        "r2": r2_score(y_test, y_pred),
                    }

                    self.models[f"sklearn_{model_name}"] = model
                    results[model_name] = {
                        "metrics": metrics,
                        "feature_importance": (
                            model.feature_importances_.tolist()
                            if hasattr(model, "feature_importances_")
                            else None
                        ),
                        "success": True,
                    }

                except Exception as e:
                    results[model_name] = {"error": str(e), "success": False}

        except Exception as e:
            return {"error": str(e)}

        return results

    def _create_lagged_features(self, ts: pd.Series, lags: int) -> tuple[np.ndarray, np.ndarray]:
        """Create lagged features for ML models."""
        data = []
        targets = []

        for i in range(lags, len(ts)):
            data.append(ts.iloc[i - lags : i].values)
            targets.append(ts.iloc[i])

        return np.array(data), np.array(targets)

    def generate_forecasts(self, ts: pd.Series, horizon: int = 30) -> dict[str, Any]:
        """Generate forecasts using all fitted models."""
        print(f"🔮 Generating forecasts for {horizon} periods...")

        forecasts = {}

        # Statsmodels forecasts
        for model_name, model in self.models.items():
            if "arima" in model_name or "sarima" in model_name:
                try:
                    forecast = model.forecast(steps=horizon)
                    confidence_intervals = model.get_forecast(steps=horizon).conf_int()

                    forecasts[model_name] = {
                        "forecast": forecast.tolist(),
                        "lower_ci": confidence_intervals.iloc[:, 0].tolist(),
                        "upper_ci": confidence_intervals.iloc[:, 1].tolist(),
                        "model_type": "statsmodels",
                    }
                except Exception as e:
                    forecasts[model_name] = {"error": str(e)}

        # Darts forecasts
        if DARTS_AVAILABLE:
            try:
                TimeSeries.from_series(ts)  # Validate conversion works
                for model_name, model in self.models.items():
                    if "darts_" in model_name:
                        try:
                            forecast = model.predict(horizon)
                            forecasts[model_name] = {
                                "forecast": forecast.values().flatten().tolist(),
                                "timestamps": [t.isoformat() for t in forecast.time_index],
                                "model_type": "darts",
                            }
                        except Exception as e:
                            forecasts[model_name] = {"error": str(e)}
            except Exception:
                pass

        # Sklearn forecasts (more complex due to autoregressive nature)
        for model_name, model in self.models.items():
            if "sklearn_" in model_name:
                try:
                    forecast = self._sklearn_forecast(ts, model, horizon)
                    forecasts[model_name] = {"forecast": forecast.tolist(), "model_type": "sklearn"}
                except Exception as e:
                    forecasts[model_name] = {"error": str(e)}

        self.forecasts = forecasts
        return forecasts

    def _sklearn_forecast(self, ts: pd.Series, model, horizon: int, lags: int = 5) -> np.ndarray:
        """Generate forecasts using sklearn models."""
        forecast = []
        current_data = ts.iloc[-lags:].values

        for _ in range(horizon):
            pred = model.predict(current_data.reshape(1, -1))[0]
            forecast.append(pred)
            # Update current_data for next prediction
            current_data = np.append(current_data[1:], pred)

        return np.array(forecast)

    def evaluate_model_performance(self, ts: pd.Series, test_size: float = 0.2) -> dict[str, Any]:
        """Evaluate all models on held-out test data."""
        print("📊 Evaluating model performance...")

        # Split data
        split_point = int(len(ts) * (1 - test_size))
        train_ts = ts[:split_point]
        test_ts = ts[split_point:]

        performance = {}

        # Re-fit models on training data and evaluate on test data
        for model_name in self.models.keys():
            try:
                if "arima" in model_name and STATSMODELS_AVAILABLE:
                    # Extract order from model name
                    if "sarima" in model_name:
                        continue  # Handle separately

                    order = (1, 1, 1)  # Default, would need to store actual order
                    temp_model = ARIMA(train_ts, order=order).fit()
                    forecast = temp_model.forecast(steps=len(test_ts))

                    performance[model_name] = self._calculate_metrics(test_ts, forecast)

                elif "darts_" in model_name and DARTS_AVAILABLE:
                    darts_train = TimeSeries.from_series(train_ts)
                    darts_test = TimeSeries.from_series(test_ts)

                    # Get model type and refit
                    model_type = model_name.replace("darts_", "")
                    if model_type == "auto_arima":
                        temp_model = AutoARIMA()
                    elif model_type == "exponential_smoothing":
                        temp_model = ExponentialSmoothing()
                    elif model_type == "theta":
                        temp_model = Theta()
                    elif model_type == "linear_regression":
                        temp_model = LinearRegressionModel(lags=5)
                    else:
                        continue

                    temp_model.fit(darts_train)
                    forecast = temp_model.predict(len(test_ts))

                    performance[model_name] = {
                        "mae": mae(darts_test, forecast),
                        "rmse": rmse(darts_test, forecast),
                        "mape": mape(darts_test, forecast),
                        "smape": smape(darts_test, forecast),
                    }

            except Exception as e:
                performance[model_name] = {"error": str(e)}

        self.model_performance = performance
        return performance

    def _calculate_metrics(self, actual: pd.Series, predicted: pd.Series) -> dict[str, float]:
        """Calculate forecasting metrics."""
        actual_vals = actual.values
        pred_vals = predicted.values if hasattr(predicted, "values") else predicted

        # Ensure same length
        min_len = min(len(actual_vals), len(pred_vals))
        actual_vals = actual_vals[:min_len]
        pred_vals = pred_vals[:min_len]

        mae_val = np.mean(np.abs(actual_vals - pred_vals))
        rmse_val = np.sqrt(np.mean((actual_vals - pred_vals) ** 2))

        # MAPE (handle division by zero)
        mape_val = (
            np.mean(np.abs((actual_vals - pred_vals) / np.where(actual_vals != 0, actual_vals, 1)))
            * 100
        )

        return {"mae": mae_val, "rmse": rmse_val, "mape": mape_val}


def run_comprehensive_analysis(
    data: pd.DataFrame, timestamp_col: str, value_cols: list[str], output_dir: str = "data"
) -> dict[str, Any]:
    """Run comprehensive statistical analysis and forecasting."""
    print("🎯 Starting Comprehensive Statistical Analysis")
    print("=" * 60)

    results = {
        "timestamp": datetime.now().isoformat(),
        "analysis_type": "comprehensive_streaming_analysis",
        "data_quality": {},
        "forecasting": {},
        "recommendations": [],
    }

    # Initialize analyzers
    quality_analyzer = StreamingDataQualityAnalyzer(verbose=True)
    forecasting_engine = StreamingForecastingEngine(verbose=True)

    # Data quality analysis
    print("\n" + "=" * 30 + " DATA QUALITY ANALYSIS " + "=" * 30)
    quality_report = quality_analyzer.analyze_data_quality(data, timestamp_col, value_cols)
    results["data_quality"] = quality_report

    # Forecasting analysis for each value column
    print("\n" + "=" * 30 + " FORECASTING ANALYSIS " + "=" * 30)
    for col in value_cols:
        if col not in data.columns:
            continue

        print(f"\n📈 Analyzing {col}...")

        try:
            # Prepare time series
            ts, prep_info = forecasting_engine.prepare_time_series(data, timestamp_col, col)

            if len(ts) < 10:
                print(f"   ⚠️ Insufficient data for {col} (only {len(ts)} points)")
                continue

            col_results = {
                "preparation": prep_info,
                "models": {},
                "forecasts": {},
                "performance": {},
            }

            # Fit multiple models
            if STATSMODELS_AVAILABLE:
                print("   🔧 Fitting ARIMA models...")
                arima_result = forecasting_engine.fit_arima_model(ts)
                col_results["models"]["arima"] = arima_result

                sarima_result = forecasting_engine.fit_sarima_model(ts)
                col_results["models"]["sarima"] = sarima_result

            if DARTS_AVAILABLE:
                print("   🔧 Fitting Darts models...")
                darts_results = forecasting_engine.fit_darts_models(ts)
                col_results["models"]["darts"] = darts_results

            if SKLEARN_AVAILABLE:
                print("   🔧 Fitting ML models...")
                sklearn_results = forecasting_engine.fit_sklearn_models(ts)
                col_results["models"]["sklearn"] = sklearn_results

            # Generate forecasts
            forecasts = forecasting_engine.generate_forecasts(ts, horizon=30)
            col_results["forecasts"] = forecasts

            # Evaluate performance
            performance = forecasting_engine.evaluate_model_performance(ts)
            col_results["performance"] = performance

            results["forecasting"][col] = col_results

        except Exception as e:
            print(f"   ❌ Error analyzing {col}: {e}")
            results["forecasting"][col] = {"error": str(e)}

    # Generate overall recommendations
    print("\n" + "=" * 30 + " GENERATING RECOMMENDATIONS " + "=" * 30)
    recommendations = _generate_analysis_recommendations(results)
    results["recommendations"] = recommendations

    # Save results
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    with open(output_path / "statistical_analysis_report.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n✅ Analysis complete! Results saved to {output_path}")
    return results


def _generate_analysis_recommendations(results: dict[str, Any]) -> list[str]:
    """Generate recommendations based on analysis results."""
    recommendations = []

    # Data quality recommendations
    if "data_quality" in results and "recommendations" in results["data_quality"]:
        recommendations.extend(results["data_quality"]["recommendations"])

    # Model performance recommendations
    if "forecasting" in results:
        for col, col_results in results["forecasting"].items():
            if "performance" in col_results:
                best_model = None
                best_mae = float("inf")

                for model_name, metrics in col_results["performance"].items():
                    if isinstance(metrics, dict) and "mae" in metrics:
                        if metrics["mae"] < best_mae:
                            best_mae = metrics["mae"]
                            best_model = model_name

                if best_model:
                    recommendations.append(
                        f"For {col}: {best_model} shows best performance (MAE: {best_mae:.3f})"
                    )

    return recommendations


if __name__ == "__main__":
    # Example usage with sample data
    print("🧪 Testing Statistical Analysis Module")

    # Create sample streaming data
    dates = pd.date_range("2024-01-01", periods=100, freq="D")
    sample_data = pd.DataFrame(
        {
            "date": dates,
            "streams": np.random.poisson(1000, 100) + np.sin(np.arange(100) * 0.1) * 200,
            "plays": np.random.poisson(500, 100) + np.cos(np.arange(100) * 0.15) * 100,
            "listeners": np.random.poisson(300, 100) + np.sin(np.arange(100) * 0.2) * 50,
        }
    )

    # Add some noise and missing values
    sample_data.loc[10:15, "streams"] = np.nan
    sample_data.loc[30:32, "plays"] = sample_data.loc[30:32, "plays"] * 3  # outliers

    # Run analysis
    results = run_comprehensive_analysis(
        data=sample_data, timestamp_col="date", value_cols=["streams", "plays", "listeners"]
    )

    print("\n🎯 Analysis Summary:")
    print(f"Quality issues detected: {len(results['data_quality'].get('recommendations', []))}")
    print(f"Columns analyzed: {len(results['forecasting'])}")
    print(f"Total recommendations: {len(results['recommendations'])}")
