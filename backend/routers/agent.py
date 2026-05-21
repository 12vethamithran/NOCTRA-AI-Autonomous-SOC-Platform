"""
routers/agent.py
=================
AI investigation agent + kill-chain narrative.

POST /agent/{session_id}/investigate/{alert_id}?deep=true
    Run the autonomous L2 investigation for one alert.
GET  /agent/{session_id}/chain-narrative
    AI-written kill-chain story for the whole session.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from engine.ai_agent import autonomous_investigation, verdict_assist
from engine.chain import ai_chain_narrative, match_chains
from session.store import session_store

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/{session_id}/investigate/{alert_id}")
async def agent_investigate(
    session_id: str, alert_id: str, deep: bool = True
) -> dict:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")

    alert = next(
        (a for a in sess.alerts if a.get("alert_id") == alert_id), None
    )
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id!r} not in this session")

    result = await autonomous_investigation(sess, alert, deep=deep)
    return {"alert_id": alert_id, "investigation": result}


@router.get("/{session_id}/verdict-assist/{alert_id}")
async def agent_verdict_assist(session_id: str, alert_id: str) -> dict:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    alert = next(
        (a for a in sess.alerts if a.get("alert_id") == alert_id), None
    )
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id!r} not in this session")
    return {"alert_id": alert_id, "assist": await verdict_assist(sess, alert)}


@router.get("/{session_id}/chain-narrative")
async def agent_chain_narrative(session_id: str) -> dict:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")

    chains = sess.attack_chains or match_chains(sess.alerts)
    narrative = await ai_chain_narrative(chains, sess.alerts)
    return {"chains": chains, "narrative": narrative}
