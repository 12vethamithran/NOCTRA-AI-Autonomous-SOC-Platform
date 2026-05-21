"""
schemas/verdict.py
==================
Analyst's TP/FP decision for a single alert.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class VerdictDecision(str, Enum):
    """Analyst's call on the alert."""

    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"


class Verdict(BaseModel):
    """A single TP/FP submission."""

    session_id: str
    alert_id: str
    decision: VerdictDecision
    fp_reason: Optional[str] = Field(
        None,
        description="Back-compat FP reason key. Still populated for FP verdicts "
                    "so the feedback loop keeps working.",
    )
    reason: Optional[str] = Field(
        None,
        description="Selected justification for the verdict (TP or FP). "
                    "Alert-specific, may be AI-suggested or 'other'.",
    )
    reason_detail: Optional[str] = Field(
        None, description="Free-text when reason is 'other' / needs elaboration"
    )
    notes: Optional[str] = Field(None, description="Manual analyst notes")
    ai_notes: Optional[str] = Field(
        None, description="AI-generated case note captured at decision time"
    )
    decided_at: datetime = Field(default_factory=datetime.utcnow)
