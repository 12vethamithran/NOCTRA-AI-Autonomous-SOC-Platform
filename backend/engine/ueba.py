"""
engine/ueba.py
==============
User and Entity Behavior Analytics (UEBA) — behavioral anomaly detection.

Detects when users or IPs deviate from baseline behavior using Isolation Forest.
Generates R011 "Behavioral Anomaly" alerts for significant deviations.
"""

from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from schemas.alert import Alert, AlertSeverity


def build_user_profiles(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    """
    Build feature vectors for each user in the DataFrame.
    Returns a dict mapping username -> feature vector dict.
    """
    if df.empty or "user" not in df.columns:
        return {}

    profiles = {}

    for user in df["user"].unique():
        if pd.isna(user) or user == "":
            continue

        user_rows = df[df["user"] == user]

        # Feature: average login hour (0-23)
        if "timestamp" in df.columns and not user_rows["timestamp"].isna().all():
            hours = user_rows["timestamp"].dt.hour
            profiles.setdefault(user, {})["login_hour_mean"] = float(hours.mean())
            profiles[user]["login_hour_std"] = float(hours.std())
        else:
            profiles.setdefault(user, {})["login_hour_mean"] = 12.0
            profiles[user]["login_hour_std"] = 0.0

        # Feature: login count
        profiles[user]["login_count"] = len(user_rows)

        # Feature: failure rate
        if "status" in df.columns:
            failed = (user_rows["status"] == "FAILED").sum()
            profiles[user]["failure_rate"] = (
                failed / len(user_rows) if len(user_rows) > 0 else 0.0
            )
        else:
            profiles[user]["failure_rate"] = 0.0

        # Feature: distinct hosts (dest_ip)
        if "dest_ip" in df.columns:
            distinct_hosts = user_rows["dest_ip"].nunique()
            profiles[user]["distinct_hosts"] = float(distinct_hosts)
        else:
            profiles[user]["distinct_hosts"] = 0.0

        # Feature: data volume mean
        if "bytes" in df.columns:
            bytes_vals = pd.to_numeric(user_rows["bytes"], errors="coerce").fillna(0)
            profiles[user]["data_volume_mean"] = float(bytes_vals.mean())
        else:
            profiles[user]["data_volume_mean"] = 0.0

    return profiles


def build_ip_profiles(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    """
    Build feature vectors for each source IP in the DataFrame.
    Returns a dict mapping ip -> feature vector dict.
    """
    if df.empty or "source_ip" not in df.columns:
        return {}

    profiles = {}

    for ip in df["source_ip"].unique():
        if pd.isna(ip) or ip == "":
            continue

        ip_rows = df[df["source_ip"] == ip]

        # Feature: distinct ports targeted
        if "port" in df.columns:
            distinct_ports = ip_rows["port"].nunique()
            profiles.setdefault(ip, {})["distinct_ports"] = float(distinct_ports)
        else:
            profiles.setdefault(ip, {})["distinct_ports"] = 0.0

        # Feature: request rate (events per minute if we have time)
        profiles[ip]["request_rate"] = float(len(ip_rows))

        # Feature: failure rate
        if "status" in df.columns:
            failed = (ip_rows["status"] == "FAILED").sum()
            profiles[ip]["failure_rate"] = (
                failed / len(ip_rows) if len(ip_rows) > 0 else 0.0
            )
        else:
            profiles[ip]["failure_rate"] = 0.0

        # Feature: unique users targeted
        if "user" in df.columns:
            unique_users = ip_rows["user"].nunique()
            profiles[ip]["unique_users_targeted"] = float(unique_users)
        else:
            profiles[ip]["unique_users_targeted"] = 0.0

    return profiles


def run_isolation_forest(
    profiles: Dict[str, Dict[str, float]], entity_type: str = "user"
) -> Dict[str, float]:
    """
    Run Isolation Forest on entity profiles.
    Returns a dict mapping entity_id -> anomaly_score (0.0-1.0).
    """
    if not profiles:
        return {}

    # Extract feature matrix (fill missing features with 0)
    feature_names = set()
    for p in profiles.values():
        feature_names.update(p.keys())

    if not feature_names:
        return {}

    X = np.array(
        [
            [profiles[entity].get(fname, 0.0) for fname in sorted(feature_names)]
            for entity in sorted(profiles.keys())
        ]
    )

    # Run Isolation Forest
    iso_forest = IsolationForest(contamination=0.1, random_state=42, n_estimators=50)
    scores = iso_forest.fit_predict(X)  # -1 for anomaly, 1 for normal

    # Convert to 0-1 scale: -1 (anomaly) -> 1.0, 1 (normal) -> 0.0
    anomaly_scores = {}
    for i, entity_id in enumerate(sorted(profiles.keys())):
        # Use decision_function for smoother scores
        decision = iso_forest.decision_function(X[i : i + 1])[0]
        # Normalize: more negative = more anomalous
        anomaly_scores[entity_id] = max(0.0, min(1.0, 1.0 - (decision + 0.5)))

    return anomaly_scores


def run_ueba(df: pd.DataFrame) -> Tuple[List[Alert], Dict[str, Any], Dict[str, Any]]:
    """
    Run full UEBA pipeline: build profiles, detect anomalies, generate R011 alerts.
    Returns: (r011_alerts, user_profiles, ip_profiles)
    """
    user_profiles = build_user_profiles(df)
    ip_profiles = build_ip_profiles(df)

    user_anomaly_scores = run_isolation_forest(user_profiles, "user")
    ip_anomaly_scores = run_isolation_forest(ip_profiles, "ip")

    behavioral_profiles = {
        "users": user_profiles,
        "ips": ip_profiles,
        "user_anomaly_scores": user_anomaly_scores,
        "ip_anomaly_scores": ip_anomaly_scores,
    }

    r011_alerts = []

    # Generate alerts for high-anomaly users
    for user, score in user_anomaly_scores.items():
        if score > 0.6:
            alert = Alert(
                alert_id=_new_alert_id(),
                rule_id="R011",
                rule_name="Behavioral Anomaly (User)",
                severity=AlertSeverity.HIGH,
                description=f"User '{user}' behavior deviates significantly from baseline (anomaly score {score:.2f})",
                timestamp=pd.Timestamp.now(tz="UTC").to_pydatetime(),
                user=user,
                event_count=0,
                mitre_technique="T1087",
                mitre_tactic="Discovery",
                anomaly_score=score,
                extra={"entity_type": "user", "baseline_violation": "behavioral_deviation"},
            )
            r011_alerts.append(alert)

    # Generate alerts for high-anomaly IPs
    for ip, score in ip_anomaly_scores.items():
        if score > 0.6:
            alert = Alert(
                alert_id=_new_alert_id(),
                rule_id="R011",
                rule_name="Behavioral Anomaly (IP)",
                severity=AlertSeverity.HIGH,
                description=f"IP '{ip}' behavior deviates significantly from baseline (anomaly score {score:.2f})",
                timestamp=pd.Timestamp.now(tz="UTC").to_pydatetime(),
                source_ip=ip,
                event_count=0,
                mitre_technique="T1087",
                mitre_tactic="Discovery",
                anomaly_score=score,
                extra={"entity_type": "ip", "baseline_violation": "behavioral_deviation"},
            )
            r011_alerts.append(alert)

    return r011_alerts, user_profiles, ip_profiles


def _new_alert_id() -> str:
    """Generate a short random alert ID."""
    import uuid

    return uuid.uuid4().hex[:12]
