"""
engine/chain.py
===============
Attack Chain Correlation — link alert sequences into kill-chain narratives.

Detects multi-stage attacks by matching temporal sequences of alerts
against known attack patterns (kill-chain stages).
"""

import uuid
from typing import Any, Dict, List

# Define known attack chain patterns
# Each pattern is a sequence of rule IDs that should fire in order
CHAIN_PATTERNS = [
    {
        "id": "APT_DATA_THEFT",
        "name": "APT Data Theft",
        "description": "Full attack chain: Recon → Brute Force → Lateral → Exfil",
        "rule_sequence": ["R008", "R001", "R004", "R005"],
        "kill_chain_stage": "Exfiltration",
        "mitre_group": "APT",
    },
    {
        "id": "BRUTE_ESCALATE",
        "name": "Brute Force + Escalation",
        "description": "Successful brute force followed by privilege escalation",
        "rule_sequence": ["R001", "R003"],
        "kill_chain_stage": "Privilege Escalation",
        "mitre_group": "Generic",
    },
    {
        "id": "RECON_MULTI_SERVICE",
        "name": "Reconnaissance + Multi-Service Attack",
        "description": "Recon followed by multi-service credential attacks",
        "rule_sequence": ["R008", "R010"],
        "kill_chain_stage": "Initial Access",
        "mitre_group": "Generic",
    },
    {
        "id": "PERSISTENCE_ESCALATION",
        "name": "Persistence + Escalation",
        "description": "New admin account creation followed by escalation",
        "rule_sequence": ["R007", "R003"],
        "kill_chain_stage": "Privilege Escalation",
        "mitre_group": "Generic",
    },
    {
        "id": "LATERAL_EXFIL",
        "name": "Lateral Movement to Exfiltration",
        "description": "Lateral movement followed by data exfiltration",
        "rule_sequence": ["R004", "R005"],
        "kill_chain_stage": "Exfiltration",
        "mitre_group": "Generic",
    },
    {
        "id": "FULL_KILL_CHAIN",
        "name": "Full Kill Chain",
        "description": "Complete attack: Recon → Auth → Escalate → Lateral → Exfil",
        "rule_sequence": ["R008", "R001", "R003", "R004", "R005"],
        "kill_chain_stage": "Exfiltration",
        "mitre_group": "APT",
    },
]


def match_chains(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Match alert sequences to known attack patterns.
    Returns a list of detected chains.

    A chain is detected when:
    1. Alerts matching the pattern rule_sequence fire in temporal order
    2. The alerts share a common source entity (source_ip or user)
    """
    detected_chains = []

    # Sort alerts by timestamp for pattern matching
    sorted_alerts = sorted(
        alerts,
        key=lambda a: a.get("timestamp", ""),
    )

    # Try to match each pattern
    for pattern in CHAIN_PATTERNS:
        rule_sequence = pattern["rule_sequence"]

        # Group alerts by source entity
        alerts_by_ip = {}
        alerts_by_user = {}

        for alert in sorted_alerts:
            if alert.get("source_ip"):
                ip = alert["source_ip"]
                if ip not in alerts_by_ip:
                    alerts_by_ip[ip] = []
                alerts_by_ip[ip].append(alert)

            if alert.get("user"):
                user = alert["user"]
                if user not in alerts_by_user:
                    alerts_by_user[user] = []
                alerts_by_user[user].append(alert)

        # Check each entity's alerts for the sequence
        for entity_type, alerts_by_entity in [
            ("ip", alerts_by_ip),
            ("user", alerts_by_user),
        ]:
            for entity_id, entity_alerts in alerts_by_entity.items():
                # Extract rule IDs in order
                alert_rules = [a.get("rule_id") for a in entity_alerts]

                # Check if rule_sequence is a subsequence of alert_rules
                if _is_subsequence(rule_sequence, alert_rules):
                    # Extract matched alerts
                    matched_indices = []
                    for rule_id in rule_sequence:
                        for idx, a in enumerate(entity_alerts):
                            if a.get("rule_id") == rule_id and idx not in matched_indices:
                                matched_indices.append(idx)
                                break

                    matched_alert_ids = [
                        entity_alerts[idx].get("alert_id")
                        for idx in sorted(matched_indices)
                    ]

                    # Confidence: how many steps matched / total steps
                    confidence = len(matched_alert_ids) / len(rule_sequence)

                    chain_obj = {
                        "chain_id": _gen_chain_id(),
                        "name": pattern["name"],
                        "description": pattern["description"],
                        "matched_alerts": matched_alert_ids,
                        "confidence": confidence,
                        "kill_chain_stage": pattern["kill_chain_stage"],
                        "mitre_group": pattern["mitre_group"],
                        "pattern_id": pattern["id"],
                        "source_entity": {
                            "type": entity_type,
                            "value": entity_id,
                        },
                    }

                    detected_chains.append(chain_obj)

                    # Tag matched alerts with "pattern_correlation"
                    for alert in entity_alerts:
                        if alert.get("alert_id") in matched_alert_ids:
                            if "detection_methods" not in alert:
                                alert["detection_methods"] = []
                            if "pattern_correlation" not in alert["detection_methods"]:
                                alert["detection_methods"].append("pattern_correlation")

    return detected_chains


def _is_subsequence(pattern: List[str], sequence: List[str]) -> bool:
    """Check if pattern is a subsequence of sequence (in order, not necessarily adjacent)."""
    if not pattern:
        return True

    pattern_idx = 0
    for item in sequence:
        if item == pattern[pattern_idx]:
            pattern_idx += 1
            if pattern_idx == len(pattern):
                return True

    return False


def _gen_chain_id() -> str:
    """Generate a unique chain ID."""
    return f"chain_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# AI kill-chain narrative
# ---------------------------------------------------------------------------
_NARRATIVE_SYSTEM_PROMPT = """You are a senior threat analyst writing the
attack-chain section of an incident report.

You are given the alerts from one session and any statically-matched chain
patterns. Reconstruct the most likely adversary storyline ACROSS the alerts —
even if it does not match a predefined pattern. Map each stage to a MITRE
ATT&CK tactic and give decisive containment guidance.

Respond ONLY with a JSON object, no prose, no fences:
{
  "has_attack_chain": true|false,
  "campaign_name": "short evocative name",
  "narrative": "3-5 sentence chronological attack story",
  "stages": [
    {"stage": "Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Lateral Movement|Collection|Exfiltration|Impact",
     "mitre_tactic": "TAxxxx name",
     "evidence": "which alerts / entities support this stage"}
  ],
  "primary_actor_entity": "the ip or user driving the campaign",
  "severity_assessment": "LOW|MEDIUM|HIGH|CRITICAL",
  "containment_recommendations": ["prioritized actions"]
}
If the alerts are unrelated noise, set has_attack_chain false and keep the
other fields short.
"""


def _heuristic_narrative(
    chains: List[Dict[str, Any]], alerts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if chains:
        worst = max(chains, key=lambda c: c.get("confidence", 0))
        return {
            "has_attack_chain": True,
            "campaign_name": worst.get("name", "Correlated Activity"),
            "narrative": (
                f"Pattern '{worst.get('name')}' matched on "
                f"{worst.get('source_entity', {}).get('value', 'an entity')}: "
                f"{worst.get('description', '')}"
            ),
            "stages": [
                {
                    "stage": c.get("kill_chain_stage", "Unknown"),
                    "mitre_tactic": c.get("mitre_group", "—"),
                    "evidence": ", ".join(c.get("matched_alerts", [])[:6]),
                }
                for c in chains
            ],
            "primary_actor_entity": worst.get("source_entity", {}).get("value", "—"),
            "severity_assessment": "HIGH",
            "containment_recommendations": [
                "Isolate the primary actor entity",
                "Preserve correlated logs for IR",
                "Reset credentials for involved accounts",
            ],
            "ai_generated": False,
        }
    return {
        "has_attack_chain": False,
        "campaign_name": "No correlated campaign",
        "narrative": (
            "No statically-matched attack chain. Configure a Gemini key for "
            "AI correlation of non-obvious multi-stage activity."
        ),
        "stages": [],
        "primary_actor_entity": "—",
        "severity_assessment": "LOW",
        "containment_recommendations": [],
        "ai_generated": False,
    }


async def ai_chain_narrative(
    chains: List[Dict[str, Any]], alerts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Produce a written kill-chain narrative. AI when available, else heuristic."""
    from engine import gemini

    if not gemini.available():
        return _heuristic_narrative(chains, alerts)

    import json

    slim_alerts = [
        {
            "alert_id": a.get("alert_id"),
            "rule_id": a.get("rule_id"),
            "rule_name": a.get("rule_name"),
            "severity": a.get("severity"),
            "source_ip": a.get("source_ip"),
            "user": a.get("user"),
            "timestamp": str(a.get("timestamp")),
            "mitre_technique": a.get("mitre_technique"),
        }
        for a in alerts
    ][:80]
    user_text = json.dumps(
        {"alerts": slim_alerts, "matched_patterns": chains}, default=str, indent=2
    )
    raw = await gemini.generate_json(
        _NARRATIVE_SYSTEM_PROMPT, user_text, temperature=0.3
    )
    if not isinstance(raw, dict):
        return _heuristic_narrative(chains, alerts)
    raw["ai_generated"] = True
    return raw
