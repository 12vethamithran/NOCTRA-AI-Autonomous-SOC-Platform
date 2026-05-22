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

import logging
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from config import settings
from engine.demo_data import build_demo_csv
from engine.classifier import score_alerts
from engine.parser import parse
from engine.rules import run_all_rules
from engine.ueba import run_ueba
from engine.dsl import run_custom_rules
from engine.shap_explainer import attach_shap_explanations
from engine.ensemble import apply_ensemble_voting
from engine.chain import match_chains
from schemas.session import IngestResponse
from session.store import session_store

log = logging.getLogger("noctra.ingest")

router = APIRouter(prefix="/ingest", tags=["ingest"])


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

    # --- 4b. Feature 1 — UEBA behavioral anomaly detection -------------------
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
        except Exception:  # noqa: BLE001
            log.exception("AI scoring crashed; alerts kept without scores")

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
