"""
routers/session.py
==================
Read / clear endpoints for a session.

    GET    /session/{id}   -> metadata (counts, timestamps, expiry)
    DELETE /session/{id}   -> wipe from RAM immediately
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Response, status

from config import settings
from schemas.session import SessionMeta
from session.store import session_store

router = APIRouter(prefix="/session", tags=["session"])


@router.get(
    "/{session_id}",
    response_model=SessionMeta,
    summary="Get metadata for an active session",
)
async def get_session(session_id: str) -> SessionMeta:
    """Return TTL / counts / parse info for an active session."""
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    expires_at = sess.last_accessed + timedelta(minutes=settings.session_ttl_minutes)
    return SessionMeta(
        session_id=sess.session_id,
        created_at=sess.created_at,
        last_accessed=sess.last_accessed,
        expires_at=expires_at,
        source_filename=sess.source_filename,
        parsed_format=sess.parsed_format,
        event_count=sess.event_count,
        alert_count=len(sess.alerts),
        verdict_count=len(sess.verdicts),
        ttl_minutes=settings.session_ttl_minutes,
    )


@router.delete(
    "/{session_id}",
    summary="Manually clear a session from RAM",
)
async def delete_session(session_id: str):
    """Wipe a session from RAM. Returns 204 on success, 404 if not found."""
    if not session_store.delete(session_id):
        raise HTTPException(404, "Session not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
