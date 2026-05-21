"""
engine/dsl.py
=============
Domain-Specific Language (DSL) for custom detection rules.

Allows analysts to define rules in YAML/JSON format without writing Python.
Validates field/operator whitelists for security.
Compiles rules into executable pandas DataFrame functions.
"""

from typing import Any, Callable, Dict, List

import pandas as pd

from schemas.alert import Alert, AlertSeverity

# Whitelisted operators to prevent injection attacks
DSL_OPERATORS = {
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

# Whitelisted DataFrame columns to prevent access to sensitive data
ALLOWED_FIELDS = {
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


def validate_rule_dsl(rule_def: Dict[str, Any]) -> None:
    """
    Validate a rule definition. Raises ValueError if invalid.
    Rule shape: {id, name, severity, mitre, conditions, logic}
    """
    if not rule_def:
        raise ValueError("Rule definition cannot be empty")

    # Required fields
    for required in ["id", "name", "severity", "conditions", "logic"]:
        if required not in rule_def:
            raise ValueError(f"Missing required field: {required}")

    # Validate severity
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if rule_def["severity"] not in valid_severities:
        raise ValueError(
            f"Invalid severity: {rule_def['severity']} (must be one of {valid_severities})"
        )

    # Validate logic
    if rule_def["logic"] not in {"AND", "OR"}:
        raise ValueError("Logic must be AND or OR")

    # Validate conditions
    conditions = rule_def.get("conditions", [])
    if not isinstance(conditions, list) or not conditions:
        raise ValueError("Conditions must be a non-empty list")

    for i, condition in enumerate(conditions):
        if not isinstance(condition, dict):
            raise ValueError(f"Condition {i} must be a dict")

        # Check required keys
        for required in ["field", "operator", "value"]:
            if required not in condition:
                raise ValueError(f"Condition {i} missing field: {required}")

        # Whitelist check
        field = condition["field"]
        if field not in ALLOWED_FIELDS:
            raise ValueError(
                f"Condition {i}: field '{field}' not in allowed list {ALLOWED_FIELDS}"
            )

        operator = condition["operator"]
        if operator not in DSL_OPERATORS:
            raise ValueError(
                f"Condition {i}: operator '{operator}' not in allowed list {DSL_OPERATORS}"
            )


def compile_rule(rule_def: Dict[str, Any]) -> Callable[[pd.DataFrame], List[Alert]]:
    """
    Compile a rule definition into a callable function.
    Returns a function that takes a DataFrame and returns a list of Alert dicts.
    """
    validate_rule_dsl(rule_def)

    rule_id = rule_def["id"]
    rule_name = rule_def["name"]
    severity = AlertSeverity(rule_def["severity"])
    logic = rule_def["logic"]
    conditions = rule_def["conditions"]
    mitre_technique = rule_def.get("mitre", None)

    def rule_func(df: pd.DataFrame) -> List[Alert]:
        """Execute the rule on a DataFrame."""
        if df.empty:
            return []

        # Build mask for each condition
        masks = []
        for cond in conditions:
            field = cond["field"]
            operator = cond["operator"]
            value = cond["value"]

            # Safety check
            if field not in df.columns:
                masks.append(pd.Series([False] * len(df)))
                continue

            col = df[field]

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
                mask = pd.Series([False] * len(df))

            masks.append(mask)

        # Combine masks with logic
        if not masks:
            return []

        if logic == "AND":
            combined_mask = masks[0]
            for m in masks[1:]:
                combined_mask = combined_mask & m
        else:  # OR
            combined_mask = masks[0]
            for m in masks[1:]:
                combined_mask = combined_mask | m

        # Create alerts for matching rows
        matching_indices = df[combined_mask].index.tolist()
        alerts = []

        for idx in matching_indices:
            alert = Alert(
                alert_id=_new_alert_id(),
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                description=f"Custom rule: {rule_name}",
                timestamp=pd.Timestamp.now(tz="UTC").to_pydatetime(),
                source_ip=df.iloc[idx].get("source_ip") if "source_ip" in df.columns else None,
                dest_ip=df.iloc[idx].get("dest_ip") if "dest_ip" in df.columns else None,
                user=df.iloc[idx].get("user") if "user" in df.columns else None,
                event_count=1,
                mitre_technique=mitre_technique,
                related_log_indices=[idx],
                extra={"rule_type": "custom_dsl"},
            )
            alerts.append(alert)

        return alerts

    return rule_func


def run_custom_rules(
    df: pd.DataFrame, custom_rules: List[Dict[str, Any]]
) -> List[Alert]:
    """
    Run all custom rules on a DataFrame.
    Returns accumulated list of alerts from all rules.
    Catches exceptions per-rule so one bad rule doesn't crash the pipeline.
    """
    alerts = []

    for rule_def in custom_rules:
        try:
            rule_func = compile_rule(rule_def)
            rule_alerts = rule_func(df)
            alerts.extend(rule_alerts)
        except Exception as e:
            # Log and skip this rule
            print(f"Warning: custom rule {rule_def.get('id', '?')} failed: {e}")
            continue

    return alerts


def _new_alert_id() -> str:
    """Generate a short random alert ID."""
    import uuid

    return uuid.uuid4().hex[:12]
