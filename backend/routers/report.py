"""
routers/report.py
=================
Stream the PDF incident report for a session.

    GET /report/{session_id}        -> application/pdf
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from engine.report_gen import build_pdf
from session.store import session_store

router = APIRouter(prefix="/report", tags=["report"])


@router.get("/{session_id}")
async def download_report(session_id: str, analyst: str = "L2 Analyst") -> Response:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    pdf_bytes = build_pdf(sess, analyst=analyst)
    filename = f"noctra_report_{session_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
