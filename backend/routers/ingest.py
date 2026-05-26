"""
routers/ingest.py
=================
POST /ingest — the entry point of the whole app.

Flow:
    1. Receive the upload (multipart). Reject if too large or empty.
    2. Auto-detect format and parse into a Pandas DataFrame.
    3. Create a fresh session in the in-RAM store.
    4. Run all 10 detection rules against the DataFrame.
    5. Score each alert with Gemini (TP probability + plain-English explanation).
       Falls back to a heuristic if the AI is unavailable.
    6. Return session_id + alerts + parse stats.

The session keeps the DataFrame around so /investigate can pull the timeline.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from config import settings
from engine.demo_data import build_demo_csv
from engine.classifier import score_alerts
from engine.parser import parse
from engine.rules import run_all_rules
from engine.ml_detector import ml_scan
from engine.ueba import run_ueba
from engine.dsl import run_custom_rules
from engine.shap_explainer import attach_shap_explanations
from engine.ensemble import apply_ensemble_voting
from engine.chain import match_chains
from schemas.session import IngestResponse
from session.store import session_store

log = logging.getLogger("noctra.ingest")

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _collapse_duplicate_alerts(alerts: list[dict]) -> list[dict]:
    """
    Collapse alerts that describe the same logical event.

    A duplicate is defined as: same (rule_id, source_ip, user, dest_ip).
    When we collapse, we keep the earliest timestamp, sum event_count, merge
    related_log_indices, and surface the collapsed count in extra. This is the
    safety net that catches any per-row rule loops we missed and stops repeated
    uploads of the same activity from compounding into a flood.

    Conservative on purpose — we never merge across rule_ids, so an analyst
    still sees each detection family separately.
    """
    if not alerts:
        return alerts

    buckets: dict[tuple, dict] = {}
    order: list[tuple] = []

    for a in alerts:
        key = (
            a.get("rule_id"),
            a.get("source_ip") or "",
            a.get("user") or "",
            a.get("dest_ip") or "",
        )
        existing = buckets.get(key)
        if existing is None:
            buckets[key] = a
            order.append(key)
            continue

        # Same logical event — merge into the earlier one.
        existing["event_count"] = int(existing.get("event_count") or 1) + int(a.get("event_count") or 1)

        # Earliest timestamp wins (preserve attack start).
        a_ts, e_ts = a.get("timestamp"), existing.get("timestamp")
        if a_ts and (not e_ts or a_ts < e_ts):
            existing["timestamp"] = a_ts

        # Highest severity wins.
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if sev_rank.get(str(a.get("severity", "")).lower(), 0) > sev_rank.get(str(existing.get("severity", "")).lower(), 0):
            existing["severity"] = a["severity"]

        # Highest tp_probability wins (most confident scoring).
        if (a.get("tp_probability") or 0) > (existing.get("tp_probability") or 0):
            existing["tp_probability"] = a["tp_probability"]

        # Merge log indices (cap to avoid bloating the payload).
        merged_idx = list(existing.get("related_log_indices") or []) + list(a.get("related_log_indices") or [])
        existing["related_log_indices"] = sorted(set(merged_idx))[:500]

        # Track the collapse in extra so the UI can show "rolled up N alerts".
        extra = dict(existing.get("extra") or {})
        extra["rolled_up_count"] = int(extra.get("rolled_up_count", 1)) + 1
        existing["extra"] = extra

    return [buckets[k] for k in order]


@router.post(
    "",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a log file, parse it, detect, score, return alerts",
)
async def ingest(file: Annotated[UploadFile, File(...)]) -> IngestResponse:
    # --- 1. Read the upload into memory (we never touch disk) -----------------
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > settings.max_upload_mb:
        raise HTTPException(
            413,
            f"File too large ({size_mb:.1f} MB). Max is {settings.max_upload_mb} MB.",
        )
    if not content:
        raise HTTPException(400, "Uploaded file is empty")

    return await _run_pipeline(file.filename, content)


class EncodedUpload(BaseModel):
    """Base64-encoded upload payload for the WAF-safe ingest path."""

    filename: str = Field(..., description="Original file name (extension is a parse hint)")
    content_b64: str = Field(..., description="Base64-encoded raw file bytes")


@router.post(
    "/raw",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a base64-encoded log file (WAF-safe path)",
)
async def ingest_raw(payload: EncodedUpload) -> IngestResponse:
    """
    Same pipeline as POST /ingest, but the file arrives base64-encoded inside a
    JSON body. Security logs legitimately contain attack payloads (Log4Shell,
    SQLi, XSS, …); a multipart upload of that raw content is flagged and dropped
    by upstream WAFs. Base64 makes the body opaque to signature matching while
    staying lossless. The browser client uses this path for all file uploads.
    """
    if not payload.filename:
        raise HTTPException(400, "No filename provided")

    b64 = payload.content_b64.strip()
    # Tolerate data-URL prefixes ("data:...;base64,XXXX") just in case.
    if "," in b64 and b64.lower().startswith("data:"):
        b64 = b64.split(",", 1)[1]
    try:
        content = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, f"Invalid base64 content: {exc}") from exc

    size_mb = len(content) / (1024 * 1024)
    if size_mb > settings.max_upload_mb:
        raise HTTPException(
            413,
            f"File too large ({size_mb:.1f} MB). Max is {settings.max_upload_mb} MB.",
        )
    if not content:
        raise HTTPException(400, "Uploaded file is empty")

    return await _run_pipeline(payload.filename, content)


@router.post(
    "/demo",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a real session from a synthetic multi-stage attack",
)
async def ingest_demo() -> IngestResponse:
    """
    Generate a realistic kill-chain dataset and run it through the SAME
    pipeline as a real upload. This produces a genuine backend session, so
    every page (Hunt, Rules, Threat Intel, AI agent, chains) is fully
    interactive in the demo — no client-only stub.
    """
    return await _run_pipeline("demo-attack-scenario.csv", build_demo_csv())


async def _run_pipeline(filename: str, content: bytes) -> IngestResponse:
    # --- 2. Parse ------------------------------------------------------------
    try:
        parsed = parse(filename, content)
    except ValueError as exc:
        raise HTTPException(415, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        log.exception("Parser crashed on %s", filename)
        raise HTTPException(500, f"Failed to parse log file: {exc}") from exc

    if parsed.event_count == 0:
        raise HTTPException(
            422,
            "The uploaded file contains no readable lines. "
            "Provide a text-based log (CSV, JSON/JSONL, Apache, Syslog, "
            "Windows Event, logfmt, or any line-oriented log).",
        )

    # --- 3. Create session and stash the DataFrame ---------------------------
    sess = session_store.create()
    sess.source_filename = filename
    sess.parsed_format = parsed.detected_format
    sess.event_count = parsed.event_count
    sess.logs = parsed.dataframe

    # --- 4. Detection rules (rule-based) ------------------------------------
    alerts = run_all_rules(parsed.dataframe)
    log.info(
        "Detection: session=%s rules_fired=%d alerts=%d",
        sess.session_id,
        len({a.rule_id for a in alerts}),
        len(alerts),
    )

    # --- 4b. ML model detection (catches what rules miss) --------------------
    try:
        ml_alerts = ml_scan(parsed.dataframe)
        # Only add ML alerts that aren't already covered by a rule alert on the same row
        rule_row_indices = {
            idx
            for a in alerts
            for idx in (a.related_log_indices or [])
        }
        novel_ml = [
            a for a in ml_alerts
            if not any(i in rule_row_indices for i in (a.related_log_indices or []))
        ]
        alerts.extend(novel_ml)
        log.info("ML detector: %d total alerts, %d novel (rule not already fired)", len(ml_alerts), len(novel_ml))
    except Exception as e:
        log.exception("ML detector crashed: %s", e)

    # --- 4c. Feature 1 — UEBA behavioral anomaly detection -------------------
    try:
        from engine.ueba import run_isolation_forest
        ueba_alerts, user_profiles, ip_profiles = run_ueba(parsed.dataframe)
        alerts.extend(ueba_alerts)

        # Compute anomaly scores
        user_anomaly_scores = run_isolation_forest(user_profiles, "user") if user_profiles else {}
        ip_anomaly_scores = run_isolation_forest(ip_profiles, "ip") if ip_profiles else {}

        sess.behavioral_profiles = {
            "users": user_profiles,
            "ips": ip_profiles,
            "user_anomaly_scores": user_anomaly_scores,
            "ip_anomaly_scores": ip_anomaly_scores,
        }
        log.info("UEBA: generated %d behavioral anomaly alerts", len(ueba_alerts))
    except Exception as e:
        log.exception("UEBA crashed: %s", e)

    # --- 4c. Feature 5 — Custom DSL rules (if defined) -----------------------
    if sess.custom_rules:
        try:
            custom_alerts = run_custom_rules(parsed.dataframe, sess.custom_rules)
            alerts.extend(custom_alerts)
            log.info("Custom DSL: generated %d custom rule alerts", len(custom_alerts))
        except Exception as e:
            log.exception("Custom DSL crashed: %s", e)

    # --- 5. AI scoring (Gemini -> heuristic fallback) ------------------------
    if alerts:
        try:
            await score_alerts(alerts)
        except Exception as exc:  # noqa: BLE001
            log.exception("AI scoring crashed (%s); alerts kept without scores", exc)

    # --- 5b. Feature 3 — SHAP feature attribution ---------------------------
    alerts_dicts = [a.model_dump(mode="json") for a in alerts]
    try:
        alerts_dicts = attach_shap_explanations(alerts_dicts, parsed.dataframe)
        log.info("SHAP: attached feature attributions to %d alerts", len(alerts_dicts))
    except Exception as e:
        log.exception("SHAP crashed: %s", e)

    # --- 5c. Feature 6 — Ensemble voting cross-confirmation ------------------
    try:
        alerts_dicts = apply_ensemble_voting(alerts_dicts, sess.behavioral_profiles)
        log.info("Ensemble: cross-checked alerts with behavioral profiles")
    except Exception as e:
        log.exception("Ensemble voting crashed: %s", e)

    # --- 5d. Feature 2 — Attack chain correlation ----------------------------
    try:
        chains = match_chains(alerts_dicts)
        sess.attack_chains = chains
        log.info("Chain correlation: detected %d attack chains", len(chains))
    except Exception as e:
        log.exception("Chain correlation crashed: %s", e)

    # --- 5e. Dedup pass — collapse identical alerts before persistence -------
    # Safety net for any per-row rule loops and for repeated uploads of the
    # same activity. Keeps the UI focused on distinct threats, not duplicates.
    pre_dedup = len(alerts_dicts)
    alerts_dicts = _collapse_duplicate_alerts(alerts_dicts)
    if pre_dedup != len(alerts_dicts):
        log.info(
            "Dedup: collapsed %d → %d alerts (suppressed %d duplicates)",
            pre_dedup, len(alerts_dicts), pre_dedup - len(alerts_dicts),
        )

    # --- 6. Persist alerts on the session ------------------------------------
    sess.alerts = alerts_dicts
    sess.detection_methods_used = ["rule_based", "behavioral_anomaly"] if sess.behavioral_profiles else ["rule_based"]

    log.info(
        "Ingest ok: session=%s file=%s format=%s rows=%d dropped=%d alerts=%d",
        sess.session_id,
        filename,
        parsed.detected_format,
        parsed.event_count,
        parsed.dropped_lines,
        len(alerts),
    )

    return IngestResponse(
        session_id=sess.session_id,
        parsed_format=parsed.detected_format,
        event_count=parsed.event_count,
        dropped_lines=parsed.dropped_lines,
        alerts=alerts,
        message=(
            f"Parsed {parsed.event_count} events from {filename!r} "
            f"({parsed.detected_format}) — {len(alerts)} alert(s) detected."
        ),
    )
