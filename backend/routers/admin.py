"""
routers/admin.py
================
POST /admin/retrain  — trigger the full ML self-upgrade cycle
GET  /admin/retrain  — poll the current / last run status
GET  /admin/pipeline — info about what each phase does

The pipeline runs the four noctra_training_data scripts in order:
  corpus_analyser → rule_synthesiser → parser_pattern_extractor → train_model

rule_config.json is hot-reloaded by rules.py automatically after synthesis,
so rule threshold changes take effect on the NEXT ingest without a restart.
parser_hints.json is loaded by parser.py at import time; a restart (or
uvicorn --reload) picks it up, but the parser degrades gracefully without it.
The ML model pkl is swapped atomically by train_model.py.

Authentication: protected by a simple bearer token (ADMIN_SECRET env var).
If ADMIN_SECRET is not set, the endpoint is disabled (403 for all requests).
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from engine.retrain_orchestrator import get_status, start_retrain, _PHASES

log = logging.getLogger("noctra.admin")

router = APIRouter(prefix="/admin", tags=["admin"])

_bearer = HTTPBearer(auto_error=False)

_PIPELINE_DESCRIPTION = [
    {
        "phase_id": p["id"],
        "name": p["name"],
        "description": p["description"],
        "script": p["script"].name,
    }
    for p in _PHASES
]


def _require_auth(credentials: HTTPAuthorizationCredentials | None) -> None:
    secret = os.environ.get("ADMIN_SECRET", "").strip()
    if not secret:
        raise HTTPException(403, "Admin endpoint disabled — set ADMIN_SECRET env var to enable")
    if credentials is None or credentials.credentials != secret:
        raise HTTPException(401, "Invalid or missing admin token")


@router.post(
    "/retrain",
    summary="Trigger the full ML self-upgrade pipeline",
)
async def trigger_retrain(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> dict:
    """
    Launches the four-phase ML upgrade cycle as a background task.
    Returns immediately — poll GET /admin/retrain for progress.

    Phases:
      1. corpus_analyser       — parse training corpus, extract rule insights
      2. rule_synthesiser      — patch rule_config.json with corpus-optimal thresholds
      3. parser_pattern_extractor — update parser_hints.json with field aliases
      4. train_model           — retrain XGBoost; gate on AUC ≥ 0.80

    rule_config.json changes take effect immediately (hot-reload).
    ML model changes take effect after the next server start.
    """
    _require_auth(credentials)

    status = get_status()
    if status["running"]:
        return {
            "queued": False,
            "reason": "A retrain pipeline is already running",
            "current_phase": status["phase"],
            "progress_pct": status["progress_pct"],
            "started_at": status["started_at"],
        }

    result = await start_retrain(background=True)
    log.info("Retrain triggered: %s", result)
    return result


@router.get(
    "/retrain",
    summary="Poll the current or last retrain pipeline status",
)
async def retrain_status(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> dict:
    """Return the live status of the running (or last completed) retrain."""
    _require_auth(credentials)
    return get_status()


@router.get(
    "/pipeline",
    summary="Describe the upgrade pipeline phases",
)
async def pipeline_info(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> dict:
    """Return metadata about each pipeline phase (no side effects)."""
    _require_auth(credentials)
    return {
        "phases": _PIPELINE_DESCRIPTION,
        "description": (
            "The ML self-upgrade pipeline analyses the training corpus, "
            "synthesises rule threshold optimisations, extracts parser field aliases, "
            "and retrains the XGBoost classifier — all without touching source code."
        ),
    }
