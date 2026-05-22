"""
main.py
=======
FastAPI app entry point for the Noctra AI backend.

Run:
    uvicorn main:app --reload --port 8000

Phase 1 wires up:
    - CORS for the Vite dev server (localhost:5173)
    - The session-store TTL sweeper (background daemon thread)
    - /ingest    (upload + parse)
    - /session   (get / delete)
    - /health    (liveness + which API keys are loaded)

Phase 2+ will add: /alerts, /investigate, /verdict, /threatintel,
/playbook, /report.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routers import alerts as alerts_router
from routers import ingest as ingest_router
from routers import investigate as investigate_router
from routers import playbook as playbook_router
from routers import session as session_router
from routers import report as report_router
from routers import threatintel as threatintel_router
from routers import verdict as verdict_router
from routers import feedback as feedback_router
from routers import custom_rules as custom_rules_router
from routers import assets as assets_router
from routers import hunt as hunt_router
from routers import graph as graph_router
from routers import agent as agent_router
from session.store import session_store

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("noctra")


# -----------------------------------------------------------------------------
# Lifespan — start/stop background work
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "Starting Noctra AI backend (ttl=%dm, sweep=%ss, max_upload=%dMB)",
        settings.session_ttl_minutes,
        settings.session_sweep_interval_seconds,
        settings.max_upload_mb,
    )
    log.info(
        "API keys loaded — gemini=%s abuseipdb=%s virustotal=%s",
        settings.gemini_ready,
        settings.abuseipdb_ready,
        settings.virustotal_ready,
    )
    session_store.start_sweeper()
    try:
        yield
    finally:
        log.info("Shutting down — stopping session sweeper")
        session_store.stop_sweeper()


# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Noctra AI API",
    description=(
        "Storageless SOC analyst platform — logs live only in RAM, "
        "sessions auto-clear after the configured TTL."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — single origin in dev. Loosen later if you deploy a different frontend URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"https://noctra-ai-autonomous-soc-platform.*\.vercel\.app",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Routers
# -----------------------------------------------------------------------------
app.include_router(ingest_router.router)
app.include_router(alerts_router.router)
app.include_router(investigate_router.router)
app.include_router(verdict_router.router)
app.include_router(playbook_router.router)
app.include_router(threatintel_router.router)
app.include_router(report_router.router)
app.include_router(session_router.router)
app.include_router(feedback_router.router)
app.include_router(custom_rules_router.router)
app.include_router(assets_router.router)
app.include_router(hunt_router.router)
app.include_router(graph_router.router)
app.include_router(agent_router.router)


# -----------------------------------------------------------------------------
# Misc endpoints
# -----------------------------------------------------------------------------
@app.get("/health", tags=["meta"])
async def health() -> dict:
    """Liveness check + which integrations are configured."""
    return {
        "status": "ok",
        "version": app.version,
        "active_sessions": session_store.count(),
        "integrations": {
            "gemini": settings.gemini_ready,
            "abuseipdb": settings.abuseipdb_ready,
            "virustotal": settings.virustotal_ready,
        },
        "ttl_minutes": settings.session_ttl_minutes,
    }


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "name": "Noctra AI API",
        "docs": "/docs",
        "health": "/health",
    }
