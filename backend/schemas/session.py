"""
schemas/session.py
==================
Response shapes for session lifecycle endpoints (ingest, get, delete).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .alert import Alert


class IngestResponse(BaseModel):
    """Returned by POST /ingest after a successful upload."""

    session_id: str = Field(..., description="Use this for every subsequent API call")
    parsed_format: str = Field(..., description="csv | json | apache | syslog | winevent")
    event_count: int = Field(..., description="Number of log rows successfully parsed")
    dropped_lines: int = Field(0, description="Malformed lines that were skipped")
    alerts: List[Alert] = Field(
        default_factory=list,
        description="Alerts detected during ingest (empty in phase-1 scaffold)",
    )
    message: str = Field(..., description="Friendly status string for the UI")


class SessionMeta(BaseModel):
    """Returned by GET /session/{id}."""

    session_id: str
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    source_filename: str
    parsed_format: str
    event_count: int
    alert_count: int
    verdict_count: int
    ttl_minutes: int
