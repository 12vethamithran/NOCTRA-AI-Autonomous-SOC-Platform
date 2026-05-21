"""
engine/shap_explainer.py
========================
Feature attribution using SHAP (SHapley Additive exPlanations).

Trains a Random Forest classifier on synthetic data at module import time.
Uses SHAP TreeExplainer to compute feature contributions for each alert.
Attaches top-5 features to every alert for explainability in the UI.
"""

import warnings
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings("ignore", category=UserWarning)

# Feature names used by the model
FEATURE_NAMES = [
    "failed_login_count",
    "distinct_ports",
    "login_hour",
    "is_admin",
    "event_frequency",
    "bytes_transferred",
    "time_window_seconds",
    "is_external_ip",
    "consecutive_failures",
    "multi_service",
]

# Global model trained at import time
_MODEL: RandomForestClassifier = None
_EXPLAINER: shap.TreeExplainer = None


def _init_model() -> None:
    """Train model on synthetic data. Called once at module load."""
    global _MODEL, _EXPLAINER

    # Generate synthetic training data: 500 samples
    np.random.seed(42)
    n_samples = 500
    X = np.random.randn(n_samples, len(FEATURE_NAMES))

    # Target: roughly 30% True Positive (1), 70% False Positive (0)
    # Bias toward TP when features are higher
    feature_sum = X.sum(axis=1)
    y = (feature_sum > np.percentile(feature_sum, 70)).astype(int)

    # Train Random Forest
    _MODEL = RandomForestClassifier(
        n_estimators=50, max_depth=6, random_state=42, n_jobs=-1
    )
    _MODEL.fit(X, y)

    # Create SHAP explainer
    _EXPLAINER = shap.TreeExplainer(_MODEL)


# Initialize on import
_init_model()


def extract_alert_features(alert: Dict[str, Any], df: pd.DataFrame) -> np.ndarray:
    """
    Extract a 10-dimensional feature vector from an alert and its related logs.
    Returns a numpy array matching FEATURE_NAMES order.
    """
    features = np.zeros(len(FEATURE_NAMES))

    # Populate from alert dict if available, else compute from related logs
    if "related_log_indices" in alert and alert["related_log_indices"]:
        try:
            related_rows = df.iloc[alert["related_log_indices"]]
        except (IndexError, KeyError):
            related_rows = pd.DataFrame()
    else:
        # Fallback: all rows matching source_ip
        if alert.get("source_ip") and not df.empty:
            related_rows = df[df.get("source_ip") == alert.get("source_ip")]
        else:
            related_rows = pd.DataFrame()

    # Feature 0: failed_login_count
    if not related_rows.empty and "status" in related_rows.columns:
        features[0] = float((related_rows["status"] == "FAILED").sum())
    else:
        features[0] = 0.0

    # Feature 1: distinct_ports
    if not related_rows.empty and "port" in related_rows.columns:
        features[1] = float(related_rows["port"].nunique())
    else:
        features[1] = 0.0

    # Feature 2: login_hour (0-23)
    if (
        not related_rows.empty
        and "timestamp" in related_rows.columns
        and not related_rows["timestamp"].isna().all()
    ):
        features[2] = float(related_rows["timestamp"].dt.hour.mean())
    else:
        features[2] = 12.0

    # Feature 3: is_admin (0 or 1)
    user = str(alert.get("user") or "")
    features[3] = 1.0 if user.lower() in {"admin", "root", "administrator"} else 0.0

    # Feature 4: event_frequency
    features[4] = float(alert.get("event_count", 0))

    # Feature 5: bytes_transferred
    if not related_rows.empty and "bytes" in related_rows.columns:
        bytes_vals = pd.to_numeric(related_rows["bytes"], errors="coerce").fillna(0)
        features[5] = float(bytes_vals.sum())
    else:
        features[5] = 0.0

    # Feature 6: time_window_seconds (dummy estimate: event_count * 10)
    features[6] = float(alert.get("event_count", 0) * 10)

    # Feature 7: is_external_ip (0 or 1)
    source_ip = alert.get("source_ip", "")
    features[7] = 1.0 if _is_external_ip(source_ip) else 0.0

    # Feature 8: consecutive_failures
    if not related_rows.empty and "status" in related_rows.columns:
        failed_mask = related_rows["status"] == "FAILED"
        # Count max consecutive FAILEDs
        consecutive = 0
        max_consecutive = 0
        for is_fail in failed_mask:
            if is_fail:
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 0
        features[8] = float(max_consecutive)
    else:
        features[8] = 0.0

    # Feature 9: multi_service (check for multiple event_types in related rows)
    if not related_rows.empty and "event_type" in related_rows.columns:
        features[9] = float(related_rows["event_type"].nunique() > 1)
    else:
        features[9] = 0.0

    return features


def explain_alert(alert: Dict[str, Any], df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Compute SHAP values for an alert and return top-5 feature attributions.
    Returns a list of dicts: [{feature, value, contribution, direction}, ...]
    """
    if _MODEL is None or _EXPLAINER is None:
        return []

    try:
        features = extract_alert_features(alert, df).reshape(1, -1)
        shap_values = _EXPLAINER.shap_values(features)

        # Normalize across SHAP versions to a 1-D per-feature vector for the
        # TP class. Possible shapes:
        #   list[ (1, nf) , (1, nf) ]        (older multiclass)
        #   ndarray (1, nf)                  (binary)
        #   ndarray (1, nf, n_classes)       (shap >= 0.45 RF)
        if isinstance(shap_values, list):
            arr = np.asarray(shap_values[1] if len(shap_values) > 1 else shap_values[0])
            shap_vals = arr[0]
        else:
            arr = np.asarray(shap_values)
            if arr.ndim == 3:          # (1, nf, n_classes) -> TP class
                shap_vals = arr[0, :, -1]
            elif arr.ndim == 2:        # (1, nf)
                shap_vals = arr[0]
            else:                      # (nf,)
                shap_vals = arr
        shap_vals = np.asarray(shap_vals, dtype=float).ravel()

        # Pair up feature names with their SHAP values
        feature_contributions = []
        for fname, fval, shap_val in zip(FEATURE_NAMES, features[0], shap_vals):
            feature_contributions.append(
                {
                    "feature": fname,
                    "value": float(fval),
                    "contribution": float(shap_val),
                    "direction": "positive" if shap_val >= 0 else "negative",
                }
            )

        # Sort by absolute contribution and take top 5
        feature_contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        return feature_contributions[:5]

    except Exception as e:
        # Fallback on any SHAP error
        return []


def attach_shap_explanations(
    alerts: List[Dict[str, Any]], df: pd.DataFrame
) -> List[Dict[str, Any]]:
    """
    Attach SHAP feature attributions to each alert dict.
    Mutates alerts in place and returns them.
    """
    for alert in alerts:
        shap_features = explain_alert(alert, df)
        alert["shap_features"] = shap_features

    return alerts


def _is_external_ip(ip: str) -> bool:
    """Check if an IP is external (not RFC1918 / loopback / link-local)."""
    if not ip:
        return False
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except (ValueError, TypeError):
        return False
