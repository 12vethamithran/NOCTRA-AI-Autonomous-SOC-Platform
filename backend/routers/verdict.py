"""
routers/verdict.py
==================
Analyst TP/FP submissions.

    POST /verdict                       -> store decision on the alert
    GET  /verdict/{session_id}          -> list of decisions for this session
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException

from schemas.verdict import Verdict, VerdictDecision
from session.store import session_store

router = APIRouter(prefix="/verdict", tags=["verdict"])


@router.post("", response_model=Verdict)
async def submit_verdict(verdict: Verdict) -> Verdict:
    sess = session_store.get(verdict.session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")

    # Confirm the alert exists in this session.
    if not any(a.get("alert_id") == verdict.alert_id for a in sess.alerts):
        raise HTTPException(404, f"Alert {verdict.alert_id!r} not in this session")

    if verdict.decision == VerdictDecision.FALSE_POSITIVE and not verdict.fp_reason:
        raise HTTPException(422, "fp_reason is required when decision=FP")

    sess.verdicts[verdict.alert_id] = verdict.model_dump(mode="json")

    # Feature 4 — accumulate feedback statistics for adaptive learning
    alert = next((a for a in sess.alerts if a.get("alert_id") == verdict.alert_id), None)
    if alert:
        rule_id = alert.get("rule_id")
        if rule_id:
            # Initialize feedback dict for this rule if not exists
            if rule_id not in sess.feedback:
                sess.feedback[rule_id] = {
                    "tp_count": 0,
                    "fp_count": 0,
                    "fp_reasons": [],
                }

            # Update counts
            if verdict.decision == VerdictDecision.TRUE_POSITIVE:
                sess.feedback[rule_id]["tp_count"] += 1
            else:
                sess.feedback[rule_id]["fp_count"] += 1
                if verdict.fp_reason:
                    sess.feedback[rule_id]["fp_reasons"].append(verdict.fp_reason)

    return verdict


@router.get("/{session_id}", response_model=List[Verdict])
async def list_verdicts(session_id: str) -> List[Verdict]:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")
    return [Verdict(**v) for v in sess.verdicts.values()]
