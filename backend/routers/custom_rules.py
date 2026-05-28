"""
routers/custom_rules.py
=======================
Custom DSL rule management — analysts can define rules without Python code.

POST /custom-rules/{session_id} — add a new rule, fire on existing logs
GET /custom-rules/{session_id} — list all custom rules in session
DELETE /custom-rules/{session_id}/{rule_id} — remove a rule
"""

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from engine.dsl import run_custom_rules, validate_rule_dsl
from schemas.alert import Alert
from session.store import session_store

router = APIRouter(tags=["custom-rules"])


@router.post("/custom-rules/{session_id}")
async def create_custom_rule(session_id: str, rule_def: Dict[str, Any]):
    """
    Add a custom DSL rule to the session and execute it on existing logs.
    Returns the rule and any new alerts it generates.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Validate rule
    try:
        validate_rule_dsl(rule_def)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # Check for ID collision
    if any(r.get("id") == rule_def["id"] for r in sess.custom_rules):
        raise HTTPException(status_code=409, detail=f"Rule ID {rule_def['id']} already exists")

    # Store rule
    sess.custom_rules.append(rule_def)

    # Fire on existing logs if available
    new_alerts = []
    if sess.logs is not None and not sess.logs.empty:
        try:
            new_alerts = run_custom_rules(sess.logs, [rule_def])
            # Convert Alert objects to dicts
            new_alerts_dicts = [
                a.model_dump(mode="json") if isinstance(a, Alert) else a
                for a in new_alerts
            ]
            sess.alerts.extend(new_alerts_dicts)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to execute rule: {str(e)}")

    return {
        "rule": rule_def,
        "new_alerts": [a.model_dump() if isinstance(a, Alert) else a for a in new_alerts],
        "alerts_count": len(sess.alerts),
    }


@router.get("/custom-rules/{session_id}")
async def list_custom_rules(session_id: str):
    """
    List all custom rules defined in this session.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    return {"rules": sess.custom_rules, "count": len(sess.custom_rules)}


@router.delete("/custom-rules/{session_id}/{rule_id}")
async def delete_custom_rule(session_id: str, rule_id: str):
    """
    Remove a custom rule from the session.
    Does not retroactively remove alerts it generated.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Find and remove the rule
    original_count = len(sess.custom_rules)
    sess.custom_rules = [r for r in sess.custom_rules if r.get("id") != rule_id]

    if len(sess.custom_rules) == original_count:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    return {"deleted": True, "rule_id": rule_id}
