"""
routers/hunt.py
===============
Threat Hunt Mode — proactive hunting with structured queries.

GET /hunt/{session_id}/templates — list built-in hunt templates
POST /hunt/{session_id} — execute a hunt query
POST /hunt/{session_id}/save-alert — save a hunt result as an alert
"""

from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from engine.hunt import HUNT_TEMPLATES, execute_hunt, nl_to_query
from session.store import session_store

router = APIRouter(tags=["hunt"])


@router.get("/hunt/{session_id}/templates")
async def list_hunt_templates(session_id: str):
    """
    List built-in hunt templates available for this session.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"templates": HUNT_TEMPLATES}


@router.post("/hunt/{session_id}")
async def execute_hunt_query(session_id: str, query: Dict[str, Any]):
    """
    Execute a hunt query on the session's logs.
    Query shape: {filters: [{field, operator, value}], group_by?, time_range?}

    Returns matching rows (up to 500), statistics, and suggested alerts.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if sess.logs is None or sess.logs.empty:
        return {
            "matching_rows": [],
            "row_count": 0,
            "statistics": {},
            "suggested_alerts": [],
        }

    try:
        result = execute_hunt(sess.logs, query)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hunt execution failed: {str(e)}")


@router.post("/hunt/{session_id}/nl")
async def natural_language_hunt(session_id: str, body: Dict[str, Any]):
    """
    Translate a plain-English hunt request into a validated query and run it.
    Body: {"query": "show failed logins from new IPs at night"}

    Returns the translated filters + interpretation alongside normal hunt
    results so the analyst sees exactly what was searched.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    nl_text = (body or {}).get("query", "").strip()
    if not nl_text:
        raise HTTPException(status_code=422, detail="Missing 'query' text")

    translation = await nl_to_query(nl_text)
    if not translation["filters"]:
        return {
            "translation": translation,
            "matching_rows": [],
            "row_count": 0,
            "statistics": {},
            "suggested_alerts": [],
        }

    if sess.logs is None or sess.logs.empty:
        result = {
            "matching_rows": [],
            "row_count": 0,
            "statistics": {},
            "suggested_alerts": [],
        }
    else:
        result = execute_hunt(sess.logs, {"filters": translation["filters"]})

    result["translation"] = translation
    return result


@router.post("/hunt/{session_id}/save-alert")
async def save_hunt_result_as_alert(session_id: str, alert_dict: Dict[str, Any]):
    """
    Save a hunt-suggested alert to the session's alert list.
    The alert dict should come from the suggested_alerts in hunt results.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Validate basic structure
    if "alert_id" not in alert_dict or "rule_id" not in alert_dict:
        raise HTTPException(status_code=422, detail="Alert missing required fields")

    # Append to alerts
    sess.alerts.append(alert_dict)

    return {
        "alert": alert_dict,
        "alerts_count": len(sess.alerts),
    }
