"""
engine/ensemble.py
==================
Ensemble detection voting — combine rule, behavioral, and pattern detection.

Cross-references rule-based alerts with UEBA anomaly scores and chain matches.
Boosts tp_probability when multiple methods confirm the same alert.
"""

from typing import Any, Dict, List


def apply_ensemble_voting(
    alerts: List[Dict[str, Any]], behavioral_profiles: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Apply ensemble voting to refine alert confidence.

    For each alert:
    - Check if source_ip or user is flagged by UEBA (anomaly_score > 0.5)
    - If so, add "behavioral_anomaly" to detection_methods
    - Update confirmation_count and boost tp_probability by 15% per extra method

    All rule-based alerts should already have detection_methods=["rule_based"].
    """
    user_anomaly_scores = behavioral_profiles.get("user_anomaly_scores", {})
    ip_anomaly_scores = behavioral_profiles.get("ip_anomaly_scores", {})

    for alert in alerts:
        # Initialize detection_methods if not set
        if "detection_methods" not in alert:
            alert["detection_methods"] = ["rule_based"]

        # Cross-check user
        if alert.get("user") in user_anomaly_scores:
            user_score = user_anomaly_scores[alert["user"]]
            if user_score > 0.5 and "behavioral_anomaly" not in alert["detection_methods"]:
                alert["detection_methods"].append("behavioral_anomaly")

        # Cross-check source IP
        if alert.get("source_ip") in ip_anomaly_scores:
            ip_score = ip_anomaly_scores[alert["source_ip"]]
            if ip_score > 0.5 and "behavioral_anomaly" not in alert["detection_methods"]:
                alert["detection_methods"].append("behavioral_anomaly")

        # Update confirmation count
        alert["confirmation_count"] = len(set(alert["detection_methods"]))

        # Boost tp_probability based on confirmation count
        if alert.get("confirmation_count", 0) >= 2:
            current_prob = alert.get("tp_probability", 0.0) or 0.0
            boosted_prob = min(1.0, current_prob * 1.15)
            alert["tp_probability"] = boosted_prob

    return alerts
