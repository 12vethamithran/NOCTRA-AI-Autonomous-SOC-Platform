"""
session/store.py
================
The ONLY place the app keeps state. Everything else is stateless.

Design
------
* A single process-wide dict, keyed by `session_id` (UUID4 string).
* Each value is a dataclass holding:
    - the parsed Pandas DataFrame (raw logs in memory)
    - the alert list (filled in by detection rules, later phase)
    - the verdict dict (TP/FP decisions per alert)
    - a small threat-intel cache (per-IP) so we don't re-hit AbuseIPDB
    - timestamps for TTL bookkeeping
* A background daemon thread sweeps expired sessions every N seconds.
* Locking with `threading.RLock` — Uvicorn workers/threads call into this
  store concurrently when handling parallel requests.

Why this design
---------------
The whole project is intentionally storageless. No DB, no Redis, no disk.
Sessions live for the analyst's working window (default 30 min) and vanish.
That keeps PII/log content from ever persisting.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from config import settings


# -----------------------------------------------------------------------------
# Session data shape
# -----------------------------------------------------------------------------
@dataclass
class SessionData:
    """Everything a single analyst session holds in RAM."""

    session_id: str
    created_at: datetime
    last_accessed: datetime

    # Source upload metadata (handy for the dashboard / report).
    source_filename: str = ""
    parsed_format: str = ""           # "csv" | "json" | "syslog" | "apache" | ...
    event_count: int = 0

    # The actual logs as a Pandas DataFrame — the single source of truth.
    # We keep an Optional so an empty session (created but not yet ingested)
    # still works.
    logs: Optional[pd.DataFrame] = None

    # Phase-2+ fields. They exist now so routers can populate them later
    # without changing this dataclass.
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    verdicts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    intel_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    analyst_notes: Dict[str, str] = field(default_factory=dict)

    # Feature 1 — UEBA behavioral profiles and anomaly scores
    behavioral_profiles: Dict[str, Any] = field(default_factory=dict)
    # shape: {"users": {user: features_dict}, "ips": {ip: features_dict},
    #         "user_anomaly_scores": {user: float}, "ip_anomaly_scores": {ip: float}}

    # Feature 2 — Attack chain correlation results
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    # each: {chain_id, name, matched_alerts, confidence, kill_chain_stage, mitre_group}

    # Feature 4 — False positive feedback loop data
    feedback: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # shape: {rule_id: {tp_count: int, fp_count: int, fp_reasons: List[str]}}

    # Feature 5 — Custom DSL rules defined by analyst
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)
    # each: {id, name, severity, mitre, conditions, logic}

    # Feature 6 — Track which detection methods ran in this session
    detection_methods_used: List[str] = field(default_factory=list)

    # Feature 7 — Asset inventory for criticality-based risk scoring
    asset_db: List[Dict[str, Any]] = field(default_factory=list)
    # each row from uploaded asset CSV: {ip, hostname, criticality, os, last_patched, owner, department}

    # Feature 9 — Cache graph data to avoid rebuilding it every request
    graph_cache: Optional[Dict[str, Any]] = None

    def touch(self) -> None:
        """Mark the session as just-used so the TTL sweeper leaves it alone."""
        self.last_accessed = datetime.now(timezone.utc)


# -----------------------------------------------------------------------------
# Store
# -----------------------------------------------------------------------------
class SessionStore:
    """Thread-safe in-RAM session store with TTL eviction."""

    def __init__(self, ttl_minutes: int, sweep_interval_seconds: int) -> None:
        self._ttl = timedelta(minutes=ttl_minutes)
        self._sweep_interval = sweep_interval_seconds
        self._sessions: Dict[str, SessionData] = {}
        self._lock = threading.RLock()

        # The sweeper thread is started lazily by start_sweeper() so tests can
        # opt out. It's a daemon so it doesn't block process shutdown.
        self._stop_event = threading.Event()
        self._sweeper_thread: Optional[threading.Thread] = None

    # --- lifecycle ----------------------------------------------------------
    def start_sweeper(self) -> None:
        """Start the background TTL sweeper. Idempotent."""
        if self._sweeper_thread and self._sweeper_thread.is_alive():
            return
        self._stop_event.clear()
        self._sweeper_thread = threading.Thread(
            target=self._sweep_loop, name="session-sweeper", daemon=True
        )
        self._sweeper_thread.start()

    def stop_sweeper(self) -> None:
        """Signal the sweeper to exit (called on FastAPI shutdown)."""
        self._stop_event.set()
        if self._sweeper_thread:
            self._sweeper_thread.join(timeout=2)

    # --- create / read / delete --------------------------------------------
    def create(self) -> SessionData:
        """Create a fresh session and return its data object."""
        now = datetime.now(timezone.utc)
        session_id = uuid.uuid4().hex
        data = SessionData(
            session_id=session_id, created_at=now, last_accessed=now
        )
        with self._lock:
            self._sessions[session_id] = data
        return data

    def get(self, session_id: str) -> Optional[SessionData]:
        """Fetch a session and refresh its last-accessed timestamp."""
        with self._lock:
            data = self._sessions.get(session_id)
            if data is None:
                return None
            data.touch()
            return data

    def delete(self, session_id: str) -> bool:
        """Explicitly remove a session. Returns True if it existed."""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def all_ids(self) -> List[str]:
        """For debugging/health endpoints only."""
        with self._lock:
            return list(self._sessions.keys())

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # --- internals ----------------------------------------------------------
    def _sweep_loop(self) -> None:
        """Background loop: every interval, drop sessions older than TTL."""
        while not self._stop_event.is_set():
            # Sleep first so we don't sweep instantly on boot.
            if self._stop_event.wait(self._sweep_interval):
                return  # told to stop
            self._sweep_once()

    def _sweep_once(self) -> int:
        """Drop expired sessions. Returns the number evicted."""
        cutoff = datetime.now(timezone.utc) - self._ttl
        evicted = 0
        with self._lock:
            expired_ids = [
                sid
                for sid, data in self._sessions.items()
                if data.last_accessed < cutoff
            ]
            for sid in expired_ids:
                # Drop the DataFrame reference explicitly so the GC reclaims it
                # quickly instead of waiting for the dict entry to fall out.
                self._sessions[sid].logs = None
                del self._sessions[sid]
                evicted += 1
        return evicted


# -----------------------------------------------------------------------------
# Module-level singleton (this is what routers import)
# -----------------------------------------------------------------------------
session_store = SessionStore(
    ttl_minutes=settings.session_ttl_minutes,
    sweep_interval_seconds=settings.session_sweep_interval_seconds,
)
