"""
routers/graph.py
================
Entity-relationship graph endpoints for investigation visualization.

GET /graph/{session_id} — full session entity graph
GET /graph/{session_id}/alert/{alert_id} — filtered 2-hop subgraph for an alert
"""

from fastapi import APIRouter, HTTPException

from engine.graph_builder import build_session_graph
from session.store import session_store

router = APIRouter(tags=["graph"])


@router.get("/graph/{session_id}")
async def get_full_graph(session_id: str):
    """
    Get the full entity-relationship graph for a session.
    Nodes are IPs, users, hosts. Edges are events between them.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if sess.logs is None or sess.logs.empty:
        return {"nodes": [], "edges": [], "stats": {}}

    # Check cache
    if sess.graph_cache is not None:
        return sess.graph_cache

    # Build graph
    alerts = [dict(a) if isinstance(a, dict) else a.model_dump() for a in sess.alerts]
    graph_data = build_session_graph(sess.logs, alerts)

    # Cache it
    sess.graph_cache = graph_data

    return graph_data


@router.get("/graph/{session_id}/alert/{alert_id}")
async def get_alert_graph(session_id: str, alert_id: str):
    """
    Get a filtered entity graph centered on a specific alert.
    Returns 2-hop subgraph around the alert's source entities (IP, user).
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if sess.logs is None or sess.logs.empty:
        return {"nodes": [], "edges": [], "stats": {}}

    # Find the alert
    alert_dict = next(
        (a for a in sess.alerts if a.get("alert_id") == alert_id), None
    )
    if not alert_dict:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Build filtered graph
    alerts = [dict(a) if isinstance(a, dict) else a.model_dump() for a in sess.alerts]
    graph_data = build_session_graph(sess.logs, alerts, alert_id_filter=alert_id)

    return graph_data
