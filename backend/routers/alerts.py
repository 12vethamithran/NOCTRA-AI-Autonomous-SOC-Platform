"""
routers/alerts.py
=================
List + retrieve alerts that were detected during ingest.

    GET /alerts/{session_id}               -> list[Alert]
    GET /alerts/{session_id}/{alert_id}    -> single Alert
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException

from schemas.alert import Alert
from session.store import session_store

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/{session_id}", response_model=List[Alert])
async def list_alerts(session_id: str) -> List[Alert]:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    return [Alert(**a) for a in sess.alerts]


@router.get("/{session_id}/{alert_id}", response_model=Alert)
async def get_alert(session_id: str, alert_id: str) -> Alert:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    for a in sess.alerts:
        if a.get("alert_id") == alert_id:
            return Alert(**a)
    raise HTTPException(404, f"Alert {alert_id!r} not in this session")
