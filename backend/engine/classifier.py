"""
engine/classifier.py
====================
Gemini-powered TP/FP scoring + plain-English explanation for each alert.

We use the Gemini 1.5 Flash REST API directly via httpx so we don't pull in
the full google-generativeai SDK. One async POST per ingest scores every alert
in a single batch (the prompt asks Gemini to return a JSON array).

If the Gemini key is missing, the call fails, or the response is malformed,
we fall back to a deterministic heuristic so the rest of the pipeline still
works. The frontend can still triage; the AI is a quality-of-life layer, not
a hard dependency.
"""

from __future__ import annotations

import json
import logging
import re
from typing import List

import httpx

from config import settings
from schemas.alert import Alert, AlertSeverity

log = logging.getLogger("noctra.classifier")

# Pinned to a stable GA model (see engine/gemini.py for why "flash-latest"
# was unreliable).
_GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)
_GEMINI_TIMEOUT = 25  # seconds — Gemini Flash is fast, but be defensive


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are a senior SOC analyst grading alerts.

For each alert below, return:
  - tp_probability: a float 0.0-1.0 (probability this is a True Positive,
    i.e. a real attack rather than benign noise)
  - explanation: 1-2 plain-English sentences a Tier-1 analyst could read aloud

Respond ONLY with a JSON array of objects in the same order as the input,
no prose, no markdown fences. Schema:
[
  {"alert_id": "<id>", "tp_probability": 0.87, "explanation": "..."},
  ...
]
"""


def _alert_to_prompt_row(a: Alert) -> dict:
    """Trim an alert down to what Gemini actually needs to score it."""
    return {
        "alert_id": a.alert_id,
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "severity": a.severity.value if isinstance(a.severity, AlertSeverity) else str(a.severity),
        "description": a.description,
        "source_ip": a.source_ip,
        "user": a.user,
        "event_count": a.event_count,
        "mitre_technique": a.mitre_technique,
        "extra": a.extra,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
async def score_alerts(alerts: List[Alert]) -> List[Alert]:
    """
    Mutate `alerts` in place, attaching `tp_probability` + `ai_explanation`.
    Returns the same list for convenience.
    """
    if not alerts:
        return alerts

    if not settings.gemini_ready:
        log.warning("Gemini key not configured — using heuristic scoring")
        return _heuristic_score(alerts)

    payload = {
        "system_instruction": {"parts": [{"text": _SYSTEM_PROMPT}]},
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": "Alerts to grade:\n"
                        + json.dumps([_alert_to_prompt_row(a) for a in alerts], indent=2),
                    }
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
            # Disable the hidden "thinking" budget — see engine/gemini.py for
            # the full rationale. Without this, batch scoring of many alerts
            # blows the token budget and silently degrades to heuristic.
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=_GEMINI_TIMEOUT) as client:
            resp = await client.post(
                _GEMINI_URL,
                params={"key": settings.gemini_api_key},
                json=payload,
            )
            if resp.status_code != 200:
                log.warning(
                    "Gemini HTTP %s — falling back to heuristic. Body: %s",
                    resp.status_code,
                    resp.text[:500],
                )
                return _heuristic_score(alerts)
            body = resp.json()
    except httpx.HTTPError as exc:
        log.warning("Gemini request failed (%s) — falling back to heuristic", exc)
        return _heuristic_score(alerts)

    # Pull the text out of the Gemini response envelope.
    try:
        text = body["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError):
        log.warning("Gemini response missing text — falling back to heuristic")
        return _heuristic_score(alerts)

    parsed = _parse_gemini_json(text)
    if not parsed:
        log.warning("Gemini returned unparseable JSON — falling back to heuristic")
        return _heuristic_score(alerts)

    # Build a lookup by alert_id to be order-tolerant.
    by_id = {p.get("alert_id"): p for p in parsed if isinstance(p, dict)}
    for a in alerts:
        match = by_id.get(a.alert_id)
        if match:
            try:
                a.tp_probability = max(0.0, min(1.0, float(match["tp_probability"])))
            except (KeyError, TypeError, ValueError):
                a.tp_probability = _heuristic_prob(a)
            a.ai_explanation = (match.get("explanation") or "").strip() or None
        else:
            a.tp_probability = _heuristic_prob(a)
            a.ai_explanation = _heuristic_explanation(a)
    log.info("Gemini scored %d alert(s)", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_gemini_json(text: str):
    """
    Gemini *usually* returns clean JSON because we asked for responseMimeType
    application/json, but defend against accidental ```json fences.
    """
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# Severity -> baseline probability when AI is unavailable.
_SEV_BASE = {
    AlertSeverity.CRITICAL: 0.82,
    AlertSeverity.HIGH:     0.68,
    AlertSeverity.MEDIUM:   0.52,
    AlertSeverity.LOW:      0.32,
}

# Tactic weighting — some MITRE tactics are very rarely benign in production logs.
_TACTIC_BOOST = {
    "Impact":               0.10,  # ransomware, mass write, log clearing
    "Credential Access":    0.07,  # LSASS, cleartext, lockout
    "Command and Control":  0.07,  # beaconing, DNS tunneling
    "Defense Evasion":      0.06,  # AV tamper, log cleared
    "Persistence":          0.04,
    "Lateral Movement":     0.04,
    "Privilege Escalation": 0.05,
    "Initial Access":       0.03,
    "Execution":            0.03,
    "Discovery":            0.02,
    "Collection":           0.02,
    "Reconnaissance":       0.01,
    "Exfiltration":         0.06,
}

# Rule fidelity — rules that fire on near-unambiguous signatures get a floor boost
# even when severity classification is lower.
_HIGH_FIDELITY_RULES = {
    "R013": 0.93,  # LSASS
    "R018": 0.96,  # Event log cleared
    "R019": 0.92,  # Security tool tampering
    "R021": 0.92,  # C2 beaconing
    "R023": 0.94,  # Mass file encryption / VSS deletion
    "R011": 0.87,  # PowerShell encoded
    "R012": 0.85,  # Process injection
    "R016": 0.86,  # Lockout storm
    "R020": 0.88,  # RDP brute
    "R024": 0.87,  # SQL injection
    "R025": 0.85,  # Web shell
    "R026": 0.92,  # IDS / Suricata signature
    "R027": 0.90,  # Cloud-storage exfil
    "R028": 0.86,  # NRD contact
    "R029": 0.88,  # Phishing
    "R030": 0.96,  # Cloud privileged role assignment
    "R031": 0.94,  # Masquerading binary
    "R032": 0.92,  # PowerShell drops exe to temp
    "R033": 0.96,  # Kerberoasting (weak TGS encryption)
    "R034": 0.97,  # Office spawned shell
    "R035": 0.90,  # LOLBin abuse
    "R036": 0.92,  # Service-account interactive logon
    "R037": 0.86,  # AWS sensitive call without MFA
    "R038": 0.98,  # CloudTrail tampering
    "R039": 0.84,  # S3 anomalous volume
    "R040": 0.88,  # SharePoint mass download
    "R041": 0.87,  # Geo anomaly
    "R042": 0.74,  # AWS recon
}


def _is_public_ip(ip: str | None) -> bool:
    """True if the IP is non-RFC1918 / non-loopback. Boosts likelihood of TP."""
    if not ip:
        return False
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _off_hours(a: Alert) -> bool:
    """True if the alert timestamp falls in 00:00–05:00 UTC (proxy for off-hours)."""
    if not a.timestamp:
        return False
    try:
        return 0 <= a.timestamp.hour < 5
    except Exception:
        return False


def _heuristic_prob(a: Alert) -> float:
    """
    Deterministic fallback score with broad signal coverage.

    Layers (each independent, capped at 0.98):
      1. Severity baseline
      2. Rule-defined pre-confidence (R011-R025 ship with high values)
      3. High-fidelity rule floor
      4. MITRE tactic weight
      5. External-source-IP boost
      6. Event-count amplification (>= 10 / >= 50 events)
      7. Off-hours boost
      8. Ensemble-confirmation bonus (multiple detection methods)
      9. Anomaly-score corroboration (UEBA z-score)
     10. R001 credential-compromise lock-in (legacy)
    """
    score = _SEV_BASE.get(a.severity, 0.5)

    # 2. Respect rule-defined pre-confidence if the rule set it.
    if a.tp_probability is not None and a.tp_probability > 0:
        score = max(score, a.tp_probability)

    # 3. High-fidelity rule floor.
    floor = _HIGH_FIDELITY_RULES.get(a.rule_id)
    if floor is not None:
        score = max(score, floor)

    # 4. Tactic weight.
    if a.mitre_tactic:
        score += _TACTIC_BOOST.get(a.mitre_tactic, 0.0)

    # 5. External source IP.
    if _is_public_ip(a.source_ip):
        score += 0.05

    # 6. Event-count amplification.
    if a.event_count >= 50:
        score += 0.06
    elif a.event_count >= 10:
        score += 0.03

    # 7. Off-hours.
    if _off_hours(a):
        score += 0.04

    # 8. Ensemble confirmation — multiple detection methods agreed.
    if getattr(a, "confirmation_count", 0) >= 2:
        score += 0.05
    if getattr(a, "confirmation_count", 0) >= 3:
        score += 0.03  # cumulative — 3 methods is very strong

    # 9. UEBA anomaly corroboration.
    if getattr(a, "anomaly_score", None) and a.anomaly_score >= 0.7:
        score += 0.04

    # 10. Legacy R001 credential-compromise marker.
    if a.rule_id == "R001" and a.extra.get("credential_compromise"):
        score = max(score, 0.95)

    return round(max(0.05, min(0.98, score)), 2)


def _heuristic_explanation(a: Alert) -> str:
    """Build a plain-English rationale that exposes the contributing signals.

    Designed so the analyst can immediately see why the heuristic landed where
    it did when Gemini is offline / rate-limited.
    """
    parts: list[str] = []
    sev = a.severity.value if isinstance(a.severity, AlertSeverity) else str(a.severity)
    parts.append(f"{sev} severity {a.rule_id} ({a.rule_name})")

    if a.rule_id in _HIGH_FIDELITY_RULES:
        parts.append("high-fidelity signature with rarely-benign payload")
    if a.mitre_tactic in {"Impact", "Credential Access", "Command and Control", "Defense Evasion"}:
        parts.append(f"maps to {a.mitre_tactic} — a tactic with very few legitimate patterns")
    if _is_public_ip(a.source_ip):
        parts.append(f"source IP {a.source_ip} is external")
    if a.event_count >= 50:
        parts.append(f"backed by {a.event_count} events (volume strongly amplifies confidence)")
    elif a.event_count >= 10:
        parts.append(f"backed by {a.event_count} events")
    if _off_hours(a):
        parts.append("fired during off-hours window (00:00–05:00 UTC)")
    if getattr(a, "confirmation_count", 0) >= 2:
        parts.append(f"corroborated by {a.confirmation_count} independent detection methods")
    if getattr(a, "anomaly_score", None) and a.anomaly_score >= 0.7:
        parts.append(f"UEBA anomaly z-score {a.anomaly_score:.2f}")

    body = " · ".join(parts)
    return (
        f"Heuristic score (AI offline) — {body}. "
        f"Final TP probability {int((a.tp_probability or 0) * 100)}%. "
        f"Recommended action: {'escalate now' if (a.tp_probability or 0) >= 0.75 else 'investigate' if (a.tp_probability or 0) >= 0.45 else 'review for FP tuning'}."
    )


def _heuristic_score(alerts: List[Alert]) -> List[Alert]:
    for a in alerts:
        a.tp_probability = _heuristic_prob(a)
        a.ai_explanation = _heuristic_explanation(a)
    return alerts
