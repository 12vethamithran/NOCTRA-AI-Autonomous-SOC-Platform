"""
routers/investigate.py
======================
Deep-dive view for one alert.

    GET /investigate/{session_id}/{alert_id}

Returns:
    {
      "alert": {...},
      "timeline": [...],       # ordered list of related log rows
      "iocs": {...},           # IPs / users / ports / domains / hashes
      "entities": {...},       # per-entity quick-look cards
    }
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from engine.enrichment import build_timeline, entity_summaries, extract_iocs
from session.store import session_store

router = APIRouter(prefix="/investigate", tags=["investigate"])


@router.get("/{session_id}/{alert_id}")
async def investigate(session_id: str, alert_id: str) -> dict:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")

    alert = next((a for a in sess.alerts if a.get("alert_id") == alert_id), None)
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id!r} not in this session")

    df = sess.logs
    if df is None or df.empty:
        raise HTTPException(410, "Session logs no longer available")

    related_idx = alert.get("related_log_indices") or []
    related = df.loc[df.index.intersection(related_idx)] if related_idx else df.iloc[0:0]

    # If a rule didn't record related rows, fall back to "everything from the
    # same source IP" so the analyst still has context.
    if related.empty and alert.get("source_ip"):
        related = df[df["source_ip"] == alert["source_ip"]]

    # Surface only the behavioral profiles relevant to this alert's entities
    # so the Behavior tab has data without shipping the whole session blob.
    profiles = sess.behavioral_profiles or {}
    src = alert.get("source_ip")
    usr = alert.get("user")
    behavioral = {
        "users": {usr: profiles.get("users", {}).get(usr)} if usr and profiles.get("users", {}).get(usr) else {},
        "ips": {src: profiles.get("ips", {}).get(src)} if src and profiles.get("ips", {}).get(src) else {},
        "user_anomaly_scores": {usr: profiles.get("user_anomaly_scores", {}).get(usr)} if usr else {},
        "ip_anomaly_scores": {src: profiles.get("ip_anomaly_scores", {}).get(src)} if src else {},
    }

    return {
        "alert": alert,
        "timeline": build_timeline(related),
        "iocs": extract_iocs(related),
        "entities": entity_summaries(related),
        "related_count": len(related),
        "behavioral_profiles": behavioral,
    }
