"""
engine/hunt.py
==============
Threat Hunt Mode — proactive hunting with structured queries.

Analysts can write hypothesis-driven queries against the log DataFrame
using pre-built templates or custom filters.
All field/operator access is whitelisted for security.
"""

from typing import Any, Dict, List

import pandas as pd

from engine import gemini

# Whitelisted operators (same as DSL)
HUNT_ALLOWED_OPERATORS = {
    "eq",
    "ne",
    "gt",
    "lt",
    "gte",
    "lte",
    "contains",
    "startswith",
    "in",
}

# Whitelisted fields (same as DSL)
HUNT_ALLOWED_FIELDS = {
    "source_ip",
    "dest_ip",
    "user",
    "event_type",
    "status",
    "bytes",
    "port",
    "timestamp",
    "raw",
}

# Built-in hunt templates
HUNT_TEMPLATES = [
    {
        "id": "off_hours",
        "name": "Off-Hours Logins",
        "description": "Login events between midnight and 6am",
        "default_filters": [
            {
                "field": "event_type",
                "operator": "contains",
                "value": "login",
            }
        ],
    },
    {
        "id": "large_outbound",
        "name": "Large Outbound Transfers",
        "description": "Data transfers exceeding 50MB",
        "default_filters": [
            {
                "field": "bytes",
                "operator": "gte",
                "value": 52428800,  # 50MB
            }
        ],
    },
    {
        "id": "multi_host_auth",
        "name": "Multi-Host Authentication",
        "description": "Same user authenticating from multiple hosts",
        "default_filters": [
            {
                "field": "event_type",
                "operator": "contains",
                "value": "login",
            },
            {
                "field": "status",
                "operator": "eq",
                "value": "SUCCESS",
            },
        ],
    },
    {
        "id": "failed_then_success",
        "name": "Failed Then Success",
        "description": "User with multiple failed logins followed by success",
        "default_filters": [
            {
                "field": "event_type",
                "operator": "contains",
                "value": "login",
            }
        ],
    },
    {
        "id": "port_sweep",
        "name": "Port Sweep",
        "description": "Single IP targeting multiple ports",
        "default_filters": [
            {
                "field": "port",
                "operator": "ne",
                "value": 0,
            }
        ],
    },
    {
        "id": "new_admin",
        "name": "New Admin Creation",
        "description": "New user accounts created with admin privileges",
        "default_filters": [
            {
                "field": "event_type",
                "operator": "contains",
                "value": "create",
            }
        ],
    },
]


def execute_hunt(df: pd.DataFrame, query: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a hunt query on a DataFrame.

    Query shape:
    {
        filters: [{field, operator, value}, ...],
        group_by?: str,
        time_range?: {start, end}  (ISO format)
    }

    Returns:
    {
        matching_rows: List[Dict],
        row_count: int,
        statistics: {by_source_ip, by_user, by_event_type},
        suggested_alerts: List[Dict]
    }
    """
    if df.empty:
        return {
            "matching_rows": [],
            "row_count": 0,
            "statistics": {},
            "suggested_alerts": [],
        }

    result_df = df.copy()

    # Apply filters
    filters = query.get("filters", [])
    for filt in filters:
        field = filt.get("field")
        operator = filt.get("operator")
        value = filt.get("value")

        # Whitelist check
        if field not in HUNT_ALLOWED_FIELDS or operator not in HUNT_ALLOWED_OPERATORS:
            continue

        if field not in result_df.columns:
            continue

        col = result_df[field]

        # Apply operator
        if operator == "eq":
            mask = col == value
        elif operator == "ne":
            mask = col != value
        elif operator == "gt":
            mask = pd.to_numeric(col, errors="coerce") > value
        elif operator == "lt":
            mask = pd.to_numeric(col, errors="coerce") < value
        elif operator == "gte":
            mask = pd.to_numeric(col, errors="coerce") >= value
        elif operator == "lte":
            mask = pd.to_numeric(col, errors="coerce") <= value
        elif operator == "contains":
            mask = col.astype(str).str.contains(str(value), case=False, na=False)
        elif operator == "startswith":
            mask = col.astype(str).str.startswith(str(value), na=False)
        elif operator == "in":
            if not isinstance(value, list):
                value = [value]
            mask = col.isin(value)
        else:
            mask = pd.Series([True] * len(result_df))

        result_df = result_df[mask]

    # Apply time range if provided
    if "time_range" in query and "timestamp" in result_df.columns:
        tr = query["time_range"]
        if "start" in tr:
            result_df = result_df[
                result_df["timestamp"] >= pd.Timestamp(tr["start"])
            ]
        if "end" in tr:
            result_df = result_df[
                result_df["timestamp"] <= pd.Timestamp(tr["end"])
            ]

    # Limit to 500 rows for safety
    result_df = result_df.head(500)

    # Convert to list of dicts
    matching_rows = []
    for _, row in result_df.iterrows():
        matching_rows.append(row.to_dict())

    # Compute statistics
    statistics = {}
    if "source_ip" in result_df.columns:
        statistics["by_source_ip"] = (
            result_df["source_ip"].value_counts().to_dict()
        )
    if "user" in result_df.columns:
        statistics["by_user"] = result_df["user"].value_counts().to_dict()
    if "event_type" in result_df.columns:
        statistics["by_event_type"] = (
            result_df["event_type"].value_counts().to_dict()
        )

    # Generate suggested alerts
    suggested_alerts = suggest_alerts_from_hunt(result_df, query)

    return {
        "matching_rows": matching_rows,
        "row_count": len(matching_rows),
        "statistics": statistics,
        "suggested_alerts": suggested_alerts,
    }


def suggest_alerts_from_hunt(
    matching_df: pd.DataFrame, query: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    If hunt results cross certain thresholds, suggest creating alerts.
    For example: if 20+ failed logins from same IP in a small time window.
    """
    suggestions = []

    # Rule: many failed logins from same IP
    if "status" in matching_df.columns and "source_ip" in matching_df.columns:
        failed_count = (matching_df["status"] == "FAILED").sum()
        if failed_count > 10:
            unique_ips = matching_df["source_ip"].nunique()
            if unique_ips <= 3:
                # Suggest as potential brute force
                for ip in matching_df["source_ip"].unique():
                    ip_failed = (
                        (matching_df["source_ip"] == ip)
                        & (matching_df["status"] == "FAILED")
                    ).sum()
                    if ip_failed > 5:
                        suggestions.append(
                            {
                                "alert_id": _new_alert_id(),
                                "rule_id": "HUNT-BF",
                                "rule_name": "Hunt Result: Suspected Brute Force",
                                "severity": "HIGH",
                                "description": f"{ip_failed} failed logins from {ip}",
                                "source_ip": ip,
                                "event_count": ip_failed,
                                "extra": {"hunt_suggested": True},
                            }
                        )

    # Rule: many unique ports from same IP
    if "port" in matching_df.columns and "source_ip" in matching_df.columns:
        for ip in matching_df["source_ip"].unique():
            ip_df = matching_df[matching_df["source_ip"] == ip]
            unique_ports = ip_df["port"].nunique()
            if unique_ports > 10:
                suggestions.append(
                    {
                        "alert_id": _new_alert_id(),
                        "rule_id": "HUNT-PS",
                        "rule_name": "Hunt Result: Port Sweep Activity",
                        "severity": "MEDIUM",
                        "description": f"{ip} scanned {unique_ports} distinct ports",
                        "source_ip": ip,
                        "event_count": len(ip_df),
                        "extra": {"hunt_suggested": True},
                    }
                )

    return suggestions


def _new_alert_id() -> str:
    """Generate a short random alert ID."""
    import uuid

    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Natural-language hunt
# ---------------------------------------------------------------------------
_NL_SYSTEM_PROMPT = f"""You translate a SOC analyst's plain-English threat-hunting
question into a structured query against a normalized log table.

You MUST only use these fields: {sorted(HUNT_ALLOWED_FIELDS)}
You MUST only use these operators: {sorted(HUNT_ALLOWED_OPERATORS)}

Field hints:
- status: typically "SUCCESS" or "FAILED" (or HTTP codes like "404")
- event_type: e.g. "login", "auth", "create", "transfer"
- bytes: integer byte count (use gte/lte for "large"/"small" transfers)
- port: integer port number
- timestamp: ISO 8601

Respond ONLY with a JSON object, no prose, no fences:
{{
  "filters": [{{"field": "...", "operator": "...", "value": "..."}}],
  "interpretation": "one sentence restating what you searched for"
}}
If the request cannot be expressed with the allowed fields, return
{{"filters": [], "interpretation": "could not translate: <reason>"}}.
"""


def _validate_filters(filters: Any) -> List[Dict[str, Any]]:
    """Drop anything not on the whitelist — never trust model output blindly."""
    clean: List[Dict[str, Any]] = []
    if not isinstance(filters, list):
        return clean
    for f in filters:
        if not isinstance(f, dict):
            continue
        field = f.get("field")
        operator = f.get("operator")
        if field in HUNT_ALLOWED_FIELDS and operator in HUNT_ALLOWED_OPERATORS:
            clean.append(
                {"field": field, "operator": operator, "value": f.get("value")}
            )
    return clean


async def nl_to_query(nl_text: str) -> Dict[str, Any]:
    """
    Translate a plain-English hunt request into a validated filter query.
    Returns {filters, interpretation, ai_generated}. Filters are always
    whitelist-validated regardless of model output.
    """
    raw = await gemini.generate_json(
        _NL_SYSTEM_PROMPT, f"Analyst request: {nl_text}", temperature=0.1
    )
    if not isinstance(raw, dict):
        return {
            "filters": [],
            "interpretation": (
                "Natural-language translation needs a configured Gemini key — "
                "use the manual filter builder instead."
            ),
            "ai_generated": False,
        }
    return {
        "filters": _validate_filters(raw.get("filters")),
        "interpretation": str(raw.get("interpretation", "")).strip(),
        "ai_generated": True,
    }
