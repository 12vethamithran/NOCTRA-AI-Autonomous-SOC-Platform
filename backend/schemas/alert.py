"""
schemas/alert.py
================
Pydantic models for alerts.

An Alert is produced by the detection engine (phase 2) and consumed by:
    - the triage page (alert queue + modal)
    - the investigation page (deep dive)
    - the dashboard (counts, charts)
    - the PDF report
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    """Severity levels — mapped to colours in the frontend."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert(BaseModel):
    """One detection event."""

    alert_id: str = Field(..., description="UUID for this alert within the session")
    rule_id: str = Field(..., description="e.g. R001")
    rule_name: str = Field(..., description="e.g. Brute Force Attack")
    severity: AlertSeverity
    description: str = Field(..., description="Human-readable summary of what fired")

    # Context
    timestamp: Optional[datetime] = Field(None, description="When the suspicious activity occurred")
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    event_count: int = Field(0, description="How many log rows back this alert")

    # MITRE ATT&CK mapping (filled in by detection rules)
    mitre_technique: Optional[str] = Field(None, description="e.g. T1110")
    mitre_tactic: Optional[str] = Field(None, description="e.g. Credential Access")

    # AI scoring (Gemini, phase 2)
    tp_probability: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Likelihood this is a True Positive (0-1)"
    )
    ai_explanation: Optional[str] = Field(
        None, description="Plain-English summary from Gemini"
    )

    # Row indices in the session DataFrame, so investigation can rebuild the timeline.
    related_log_indices: List[int] = Field(default_factory=list)

    # Free-form bag for rule-specific details.
    extra: Dict[str, Any] = Field(default_factory=dict)

    # Feature 1 — UEBA behavioral anomaly detection
    anomaly_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Isolation Forest anomaly score for source entity"
    )

    # Feature 3 — SHAP feature attribution for explainability
    shap_features: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Top-5 SHAP feature attributions [{feature, value, contribution, direction}]",
    )

    # Feature 6 — Ensemble detection voting
    detection_methods: List[str] = Field(
        default_factory=list,
        description="Which detection methods flagged this [rule_based, behavioral_anomaly, pattern_correlation]",
    )
    confirmation_count: int = Field(
        0, description="Number of independent detection methods that confirmed this alert"
    )

    # Feature 7 — Asset context and risk scoring
    asset_context: Optional[Dict[str, Any]] = Field(
        None, description="Matched asset record if IP known in asset inventory"
    )
    risk_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=2.0,
        description="tp_probability × criticality_multiplier (adjusted for asset criticality)",
    )
