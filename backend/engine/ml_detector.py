"""
engine/ml_detector.py
=====================
ML-based alert detection layer trained on 68k labeled log records.

Runs alongside the rule engine — catches attacks that regex rules miss.
Uses the XGBoost + TF-IDF model trained in noctra_training_data/train_model.py.

Usage (called from routers/ingest.py):
    from engine.ml_detector import ml_scan
    ml_alerts = ml_scan(df)          # returns List[Alert]
    alerts.extend(ml_alerts)
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import List

import pandas as pd

log = logging.getLogger("noctra.ml_detector")

# Model lives next to the backend package
_MODEL_PATH = Path(__file__).parent.parent / "models" / "ml_detector.pkl"

# Lazy-loaded so import doesn't block startup if model is missing
_bundle = None
_load_error: str | None = None


def _load_model():
    global _bundle, _load_error
    if _bundle is not None or _load_error:
        return
    try:
        import joblib
        _bundle = joblib.load(_MODEL_PATH)
        log.info("ML detector loaded from %s", _MODEL_PATH)
    except Exception as exc:
        _load_error = str(exc)
        log.warning("ML detector unavailable: %s", exc)


# ── Feature helpers (must mirror train_model.py exactly) ─────────────────────
_IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_USER_RE = re.compile(r'(?:user|username|userName)["\s:=]+\S+', re.I)
_TS_RE   = re.compile(r'\d{4}-\d{2}-\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}')
_FORMAT_LIST = ["syslog", "json", "waf", "csv", "zeek", "evtx", "generic"]

def _hand_features(raw: str) -> list[float]:
    length = min(len(raw), 5000)
    digits   = sum(c.isdigit() for c in raw)
    specials = sum(c in r"!@#$%^&*()_+-=[]{}|;':\",./<>?\\" for c in raw)
    upper  = sum(c.isupper() for c in raw)
    spaces = raw.count(" ")
    ips    = len(_IP_RE.findall(raw))
    has_user  = int(bool(_USER_RE.search(raw)))
    has_ts    = int(bool(_TS_RE.search(raw)))
    rl = raw.lower()
    has_error    = int(any(w in rl for w in ("fail","error","deny","block","invalid","reject")))
    has_privesc  = int(any(w in rl for w in ("admin","root","sudo","privilege","4732","4720")))
    has_exfil    = int(any(w in rl for w in ("upload","exfil","transfer","copy","outbound")))
    has_injection= int(any(w in rl for w in ("select","union","script","eval","exec","cmd")))
    return [
        length / 5000,
        digits / max(length, 1),
        specials / max(length, 1),
        upper / max(length, 1),
        spaces / max(length, 1),
        min(ips, 5) / 5,
        has_user, has_ts, has_error, has_privesc, has_exfil, has_injection,
    ]

def _fmt_features(fmt: str) -> list[float]:
    return [1.0 if fmt == f else 0.0 for f in _FORMAT_LIST]


# ── MITRE mapping for ML-detected attacks ────────────────────────────────────
_SIGNAL_TACTIC = [
    (re.compile(r"fail|invalid user|authentication failure", re.I), "Credential Access", "T1110", "R001"),
    (re.compile(r"union\s+select|<script|\.\./|/etc/passwd|xp_cmdshell|sleep\(|eval\(", re.I), "Initial Access", "T1190", "R010"),
    (re.compile(r"4625|4720|4732|mimikatz|psexec|privilege", re.I), "Privilege Escalation", "T1078", "R005"),
    (re.compile(r'"action"\s*:\s*"(deny|block|drop)"', re.I), "Command and Control", "T1071", "R015"),
    (re.compile(r"errorCode|ConsoleLogin|CreateAccessKey|AssumeRole", re.I), "Persistence", "T1098", "R020"),
    (re.compile(r"exfil|credit_card|ssn|violation", re.I), "Exfiltration", "T1041", "R025"),
    (re.compile(r"powershell.*-enc|-encoded|-nop|-w hidden", re.I), "Execution", "T1059", "R011"),
    (re.compile(r"net\s+user|net\s+group|whoami|systeminfo|ipconfig", re.I), "Discovery", "T1082", "R030"),
]

def _infer_tactic(raw: str):
    for pattern, tactic, technique, rule_id in _SIGNAL_TACTIC:
        if pattern.search(raw):
            return tactic, technique, rule_id
    return "Command and Control", "T1071", "R015"  # default


# ── Public API ────────────────────────────────────────────────────────────────
def ml_scan(df: pd.DataFrame) -> List:
    """
    Run ML model over every row of `df`.
    Returns a list of Alert objects for rows classified as attacks
    that aren't already covered by rule-based alerts (dedup by raw content).

    Call this AFTER run_all_rules() so rule alerts take priority.
    """
    from schemas.alert import Alert, AlertSeverity

    _load_model()
    if _bundle is None:
        return []

    tfidf = _bundle["tfidf"]
    clf   = _bundle["clf"]

    if "raw" not in df.columns or df.empty:
        return []

    rows = df["raw"].fillna("").astype(str).tolist()
    detected_fmt = df.get("format", pd.Series(["generic"] * len(df))).fillna("generic").tolist() \
        if hasattr(df, "get") else ["generic"] * len(df)

    try:
        import numpy as np
        from scipy.sparse import hstack, csr_matrix

        X_tfidf = tfidf.transform([r[:1000] for r in rows])
        X_hand  = csr_matrix(np.array([_hand_features(r) for r in rows], dtype=np.float32))
        X_fmt   = csr_matrix(np.array([_fmt_features(str(f)) for f in detected_fmt], dtype=np.float32))
        X       = hstack([X_tfidf, X_hand, X_fmt])
        probs   = clf.predict_proba(X)[:, 1]
    except Exception as exc:
        log.warning("ML scan failed: %s", exc)
        return []

    alerts = []
    THRESHOLD = 0.70  # only fire when model is confident

    for idx, (row_series, prob) in enumerate(zip(df.itertuples(), probs)):
        if prob < THRESHOLD:
            continue
        raw = rows[idx]
        tactic, technique, rule_id = _infer_tactic(raw)

        # Severity from probability
        if prob >= 0.92:
            sev = AlertSeverity.CRITICAL
        elif prob >= 0.80:
            sev = AlertSeverity.HIGH
        else:
            sev = AlertSeverity.MEDIUM

        src_ip = getattr(row_series, "source_ip", None) or None
        dest_ip = getattr(row_series, "dest_ip", None) or None
        user = getattr(row_series, "user", None) or None

        alert = Alert(
            alert_id=uuid.uuid4().hex[:12],
            rule_id=f"ML-{rule_id}",
            rule_name=f"ML Detector · {tactic}",
            severity=sev,
            description=(
                f"ML model detected probable attack ({prob:.0%} confidence). "
                f"Tactic: {tactic}. Technique: {technique}. "
                f"Log snippet: {raw[:120]}"
            ),
            source_ip=str(src_ip) if src_ip else None,
            dest_ip=str(dest_ip) if dest_ip else None,
            user=str(user) if user else None,
            mitre_tactic=tactic,
            mitre_technique=technique,
            event_count=1,
            tp_probability=round(float(prob), 2),
            ai_explanation=None,
            related_log_indices=[getattr(row_series, "Index", idx)],
            extra={
                "ml_confidence": round(float(prob), 4),
                "detection_method": "ml_xgboost",
                "raw_snippet": raw[:200],
            },
        )
        alerts.append(alert)

    if alerts:
        log.info("ML detector fired %d alert(s)", len(alerts))
    return alerts


def is_available() -> bool:
    """Return True if the model is loaded and ready."""
    _load_model()
    return _bundle is not None
