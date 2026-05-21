"""
engine/ai_agent.py
==================
Autonomous Investigation Agent.

The differentiator: most SIEM/SOC tools *detect* but leave the analyst to
manually pivot, correlate and write the narrative. This agent takes a
single alert and runs the L2 investigation itself — it pulls the timeline,
extracts IOCs, finds related alerts that share an entity, folds in UEBA /
ensemble / chain signals, then asks Gemini for a verdict recommendation
*with reasoning* plus concrete next actions and pivot hunts.

`deep=False` is the lightweight triage co-pilot variant (faster, used per
row in the queue). `deep=True` is the full investigation.

Always returns a structured result. If Gemini is unavailable the verdict,
reasoning and actions are derived deterministically so the panel still
works offline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd

from engine import gemini
from engine.enrichment import build_timeline, entity_summaries, extract_iocs

_SYSTEM_PROMPT = """You are an autonomous Tier-2 SOC investigator.

You are given ONE alert plus the investigation context already gathered for
you (timeline, IOCs, entities, related alerts on the same entity, and which
independent detection methods confirmed it).

Decide the verdict and justify it the way a senior analyst would in a case
note. Be decisive but evidence-driven. Recommend ESCALATE only when there is
credible evidence of an active, multi-stage or high-impact compromise.

Respond ONLY with a JSON object, no prose, no markdown fences:
{
  "verdict_recommendation": "TP" | "FP" | "ESCALATE",
  "confidence": 0.0-1.0,
  "summary": "2-3 sentence analyst case note",
  "reasoning_steps": ["ordered investigative reasoning, 3-6 bullets"],
  "key_findings": ["the specific evidence that drove the verdict"],
  "next_best_actions": ["concrete, prioritized response actions"],
  "pivot_hunts": [
    {"description": "what this hunt would reveal",
     "filters": [{"field": "<one of source_ip,dest_ip,user,event_type,status,bytes,port>",
                  "operator": "<eq,ne,gt,lt,gte,lte,contains,startswith,in>",
                  "value": "<value>"}]}
  ]
}
"""


def _related_rows(sess, alert: Dict[str, Any]) -> pd.DataFrame:
    df = sess.logs
    if df is None or df.empty:
        return pd.DataFrame()
    idx = alert.get("related_log_indices") or []
    rows = df.loc[df.index.intersection(idx)] if idx else df.iloc[0:0]
    if rows.empty and alert.get("source_ip") and "source_ip" in df.columns:
        rows = df[df["source_ip"] == alert["source_ip"]]
    return rows


def _related_alerts(sess, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for a in sess.alerts:
        if a.get("alert_id") == alert.get("alert_id"):
            continue
        if (alert.get("source_ip") and a.get("source_ip") == alert.get("source_ip")) or (
            alert.get("user") and a.get("user") == alert.get("user")
        ):
            out.append(
                {
                    "rule_id": a.get("rule_id"),
                    "rule_name": a.get("rule_name"),
                    "severity": a.get("severity"),
                    "timestamp": str(a.get("timestamp")),
                }
            )
    return out[:25]


def _gather_context(sess, alert: Dict[str, Any], deep: bool) -> Dict[str, Any]:
    rows = _related_rows(sess, alert)
    ctx: Dict[str, Any] = {
        "alert": {
            k: alert.get(k)
            for k in (
                "rule_id",
                "rule_name",
                "severity",
                "description",
                "source_ip",
                "dest_ip",
                "user",
                "event_count",
                "mitre_technique",
                "mitre_tactic",
                "tp_probability",
                "anomaly_score",
                "detection_methods",
                "confirmation_count",
            )
        },
        "related_alerts": _related_alerts(sess, alert),
        "iocs": extract_iocs(rows),
    }
    profiles = sess.behavioral_profiles or {}
    ctx["ueba"] = {
        "user_anomaly": (profiles.get("user_anomaly_scores") or {}).get(alert.get("user")),
        "ip_anomaly": (profiles.get("ip_anomaly_scores") or {}).get(alert.get("source_ip")),
    }
    ctx["chains"] = [
        {"name": c.get("name"), "kill_chain_stage": c.get("kill_chain_stage")}
        for c in (sess.attack_chains or [])
        if alert.get("alert_id") in (c.get("matched_alerts") or [])
    ]
    if deep:
        ctx["timeline"] = build_timeline(rows)[:40]
        ctx["entities"] = entity_summaries(rows)
    return ctx


def _heuristic_result(alert: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    prob = alert.get("tp_probability") or 0.0
    methods = alert.get("detection_methods") or []
    confirms = alert.get("confirmation_count") or len(set(methods))
    chains = ctx.get("chains") or []

    if chains or (prob >= 0.8 and confirms >= 2):
        verdict = "ESCALATE"
    elif prob >= 0.6:
        verdict = "TP"
    elif prob <= 0.3:
        verdict = "FP"
    else:
        verdict = "TP" if confirms >= 2 else "FP"

    findings = []
    if confirms >= 2:
        findings.append(
            f"Confirmed by {confirms} independent detection methods ({', '.join(methods)})."
        )
    if chains:
        findings.append(
            "Alert participates in a correlated attack chain: "
            + ", ".join(c["name"] for c in chains if c.get("name"))
            + "."
        )
    if ctx.get("ueba", {}).get("ip_anomaly") or ctx.get("ueba", {}).get("user_anomaly"):
        findings.append("UEBA flagged the source entity as behaviourally anomalous.")
    if ctx.get("related_alerts"):
        findings.append(
            f"{len(ctx['related_alerts'])} other alert(s) share the same entity."
        )
    if not findings:
        findings.append(
            f"Single rule detection ({alert.get('rule_id')}) with TP probability {prob:.0%}."
        )

    actions_by_verdict = {
        "ESCALATE": [
            "Escalate to Tier-3 / incident response immediately",
            f"Contain source {alert.get('source_ip') or alert.get('user') or 'entity'} (block / isolate)",
            "Preserve related logs and snapshot affected hosts",
            "Force credential reset for involved accounts",
        ],
        "TP": [
            f"Block / rate-limit source {alert.get('source_ip') or 'entity'}",
            "Reset affected account credentials and enforce MFA",
            "Sweep for the same indicators across other assets",
        ],
        "FP": [
            "Document the false-positive rationale",
            "Consider a tuning exception for this rule + entity",
            "No containment action required",
        ],
    }

    return {
        "verdict_recommendation": verdict,
        "confidence": round(min(0.95, max(0.4, prob if verdict != "FP" else 1 - prob)), 2),
        "summary": (
            f"Heuristic assessment (AI offline): {alert.get('rule_name')} on "
            f"{alert.get('source_ip') or alert.get('user') or 'entity'} — "
            f"recommended verdict {verdict} based on TP probability {prob:.0%} "
            f"and {confirms} confirming method(s)."
        ),
        "reasoning_steps": [
            f"Rule {alert.get('rule_id')} fired with severity {alert.get('severity')}.",
            f"Model TP probability is {prob:.0%}.",
            f"{confirms} independent detection method(s) confirmed it.",
            "Correlated attack chain present." if chains else "No correlated chain.",
        ],
        "key_findings": findings,
        "next_best_actions": actions_by_verdict[verdict],
        "pivot_hunts": _heuristic_pivots(alert),
        "ai_generated": False,
    }


def _heuristic_pivots(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    pivots = []
    if alert.get("source_ip"):
        pivots.append(
            {
                "description": "All activity from this source IP across the dataset",
                "filters": [
                    {"field": "source_ip", "operator": "eq", "value": alert["source_ip"]}
                ],
            }
        )
    if alert.get("user"):
        pivots.append(
            {
                "description": "Every event involving this user account",
                "filters": [
                    {"field": "user", "operator": "eq", "value": alert["user"]}
                ],
            }
        )
    return pivots


def _sanitize(result: Any, alert: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return _heuristic_result(alert, ctx)
    verdict = str(result.get("verdict_recommendation", "")).upper()
    if verdict not in {"TP", "FP", "ESCALATE"}:
        verdict = _heuristic_result(alert, ctx)["verdict_recommendation"]
    try:
        conf = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5

    def _list(key: str) -> List:
        v = result.get(key)
        return v if isinstance(v, list) else []

    return {
        "verdict_recommendation": verdict,
        "confidence": round(conf, 2),
        "summary": str(result.get("summary", "")).strip()
        or "AI investigation complete.",
        "reasoning_steps": [str(x) for x in _list("reasoning_steps")][:8],
        "key_findings": [str(x) for x in _list("key_findings")][:8],
        "next_best_actions": [str(x) for x in _list("next_best_actions")][:8],
        "pivot_hunts": [p for p in _list("pivot_hunts") if isinstance(p, dict)][:5],
        "ai_generated": True,
    }


_VERDICT_ASSIST_PROMPT = """You are assisting a SOC analyst about to record a
TP/FP verdict on the alert below.

Produce decision support that is SPECIFIC to THIS alert and its context (the
entities, counts, timeline, related alerts, detection methods). Do not give
generic boilerplate — reference the actual IPs/users/numbers.

Respond ONLY with a JSON object, no prose, no fences:
{
  "expanded_description": "4-6 sentence precise account of what happened, the
     entities involved, why the rule fired, and the blast radius",
  "ai_notes": "2-4 sentence analyst case note in first person, as if written
     by a senior analyst reviewing this alert",
  "tp_reasons": ["3-5 alert-specific reasons this is likely a TRUE positive"],
  "fp_reasons": ["3-5 alert-specific reasons this could be a FALSE positive"],
  "recommended_verdict": "TP" | "FP",
  "ai_playbook": [
    {"phase": "Immediate|Contain|Investigate|Remediate|Harden|Report",
     "action": "concrete step referencing the real entities in this alert"}
  ]
}
"""


def _heuristic_verdict_assist(alert: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    rid = alert.get("rule_id", "")
    ip = alert.get("source_ip") or "the source"
    user = alert.get("user") or "the account"
    prob = alert.get("tp_probability") or 0.0
    methods = alert.get("detection_methods") or []
    confirms = alert.get("confirmation_count") or len(set(methods))
    rec = "TP" if (prob >= 0.6 or confirms >= 2 or ctx.get("chains")) else "FP"

    tp_reasons = [
        f"Detection rule {rid} fired on {ip} with model TP probability {prob:.0%}.",
        f"{confirms} independent detection method(s) agree: {', '.join(methods) or 'rule_based'}.",
    ]
    if ctx.get("chains"):
        tp_reasons.append(
            "Alert is part of a correlated multi-stage attack chain on the same entity."
        )
    if ctx.get("related_alerts"):
        tp_reasons.append(
            f"{len(ctx['related_alerts'])} other alert(s) involve the same entity in this window."
        )
    if ctx.get("ueba", {}).get("ip_anomaly") or ctx.get("ueba", {}).get("user_anomaly"):
        tp_reasons.append("UEBA flagged the entity as behaviourally anomalous.")

    fp_reasons = [
        f"{ip} could be a sanctioned scanner, monitoring probe, or known good source.",
        f"{user} activity may be a scheduled job, automation, or admin maintenance.",
        "Volume/threshold could be a noisy baseline rather than an attack.",
        "No corroborating threat-intel or chain context (verify before dismissing).",
    ]

    pb = {
        "R001": [
            ("Immediate", f"Block {ip} at the perimeter if still active."),
            ("Contain", f"Lock {user} if any login succeeded after the failures."),
            ("Investigate", f"Enumerate every authentication attempt from {ip} and the targeted accounts."),
            ("Remediate", f"Force password reset for {user} and enforce MFA."),
            ("Report", "Record IOCs and credential-compromise status."),
        ],
        "R005": [
            ("Immediate", f"Throttle/cut the egress path to {alert.get('dest_ip') or 'the external IP'}."),
            ("Contain", f"Isolate the host behind {ip}."),
            ("Investigate", "Identify what data set was staged/transferred and its sensitivity."),
            ("Report", "Notify DLP / data-owner and log the volume exfiltrated."),
        ],
    }.get(rid, [
        ("Immediate", f"Triage {ip}/{user} and decide containment vs monitor."),
        ("Investigate", f"Pull the full timeline for {ip} and pivot on related alerts."),
        ("Remediate", "Apply the rule-specific control and tune the detection."),
        ("Report", "Document the decision and IOCs."),
    ])

    return {
        "expanded_description": (
            f"Rule {rid} ({alert.get('rule_name')}) fired on {ip}"
            + (f" targeting {user}" if alert.get("user") else "")
            + f". {alert.get('description','')} The detection was confirmed by "
            f"{confirms} method(s) ({', '.join(methods) or 'rule_based'}) with a "
            f"model TP probability of {prob:.0%}."
            + (" It also participates in a correlated attack chain."
               if ctx.get("chains") else "")
        ),
        "ai_notes": (
            f"(AI offline — heuristic) Reviewed {rid} on {ip}. Confidence {prob:.0%}, "
            f"{confirms} confirming method(s). Recommending {rec}; verify entity "
            f"reputation and related activity before finalizing."
        ),
        "tp_reasons": tp_reasons,
        "fp_reasons": fp_reasons,
        "recommended_verdict": rec,
        "ai_playbook": [{"phase": p, "action": a} for p, a in pb],
        "ai_generated": False,
    }


async def verdict_assist(sess, alert: Dict[str, Any]) -> Dict[str, Any]:
    """Decision support for the analyst verdict UI (reasons, notes, playbook)."""
    ctx = _gather_context(sess, alert, deep=True)
    if not gemini.available():
        return _heuristic_verdict_assist(alert, ctx)

    import json

    raw = await gemini.generate_json(
        _VERDICT_ASSIST_PROMPT,
        "Alert + context:\n" + json.dumps(ctx, default=str, indent=2),
        temperature=0.25,
    )
    if not isinstance(raw, dict):
        return _heuristic_verdict_assist(alert, ctx)

    def _l(k):
        v = raw.get(k)
        return [str(x) for x in v][:6] if isinstance(v, list) else []

    fallback = _heuristic_verdict_assist(alert, ctx)
    return {
        "expanded_description": str(raw.get("expanded_description", "")).strip()
        or fallback["expanded_description"],
        "ai_notes": str(raw.get("ai_notes", "")).strip() or fallback["ai_notes"],
        "tp_reasons": _l("tp_reasons") or fallback["tp_reasons"],
        "fp_reasons": _l("fp_reasons") or fallback["fp_reasons"],
        "recommended_verdict": "FP"
        if str(raw.get("recommended_verdict", "")).upper() == "FP"
        else "TP",
        "ai_playbook": [
            p for p in raw.get("ai_playbook", []) if isinstance(p, dict)
        ][:8]
        or fallback["ai_playbook"],
        "ai_generated": True,
    }


async def autonomous_investigation(
    sess, alert: Dict[str, Any], deep: bool = True
) -> Dict[str, Any]:
    ctx = _gather_context(sess, alert, deep)

    if not gemini.available():
        return _heuristic_result(alert, ctx)

    import json

    mode = "FULL investigation" if deep else "QUICK triage co-pilot"
    user_text = (
        f"Mode: {mode}\n\nInvestigation context:\n"
        + json.dumps(ctx, default=str, indent=2)
    )
    raw = await gemini.generate_json(_SYSTEM_PROMPT, user_text, temperature=0.25)
    if raw is None:
        return _heuristic_result(alert, ctx)
    return _sanitize(raw, alert, ctx)
