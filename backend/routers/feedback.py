"""
routers/feedback.py
===================
Feedback insights endpoint — expose learning from analyst verdicts.

GET /feedback/{session_id} returns per-rule TP/FP statistics and threshold suggestions.
"""

from fastapi import APIRouter, HTTPException

from session.store import session_store

router = APIRouter(tags=["feedback"])


@router.get("/feedback/{session_id}")
async def get_feedback(session_id: str):
    """
    Get feedback insights for a session.
    Returns per-rule TP/FP counts, rates, and threshold suggestions.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    feedback_store = sess.feedback
    insights = []

    for rule_id, stats in feedback_store.items():
        tp_count = stats.get("tp_count", 0)
        fp_count = stats.get("fp_count", 0)
        fp_reasons = stats.get("fp_reasons", [])

        total = tp_count + fp_count
        fp_rate = fp_count / total if total > 0 else 0.0

        # Generate suggestion if FP rate is high
        suggestion = None
        if fp_rate > 0.4:
            suggestion = (
                f"High false positive rate ({fp_rate:.0%}). Consider raising threshold for {rule_id}."
            )

        # Most common FP reasons
        common_fp_reasons = []
        if fp_reasons:
            from collections import Counter

            reason_counts = Counter(fp_reasons)
            common_fp_reasons = [r for r, _ in reason_counts.most_common(3)]

        insights.append(
            {
                "rule_id": rule_id,
                "tp_count": tp_count,
                "fp_count": fp_count,
                "fp_rate": round(fp_rate, 3),
                "suggestion": suggestion,
                "common_fp_reasons": common_fp_reasons,
            }
        )

    # Sort by FP rate descending
    insights.sort(key=lambda x: x["fp_rate"], reverse=True)

    # Generate summary
    total_verdicts = sum(i["tp_count"] + i["fp_count"] for i in insights)
    total_tp = sum(i["tp_count"] for i in insights)
    summary = f"Session processed {total_verdicts} verdicts: {total_tp} TP, {total_verdicts - total_tp} FP."

    return {"insights": insights, "summary": summary}
