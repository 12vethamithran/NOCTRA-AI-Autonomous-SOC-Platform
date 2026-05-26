"""
engine/retrain_scheduler.py
============================
Background scheduler that auto-triggers the ML self-upgrade pipeline
on a configurable interval (default: daily at 03:00 UTC).

Wired into the FastAPI lifespan in main.py.

Environment variables:
  RETRAIN_SCHEDULE_HOURS   — interval in hours between runs (default: 24)
                             Set to 0 to disable the scheduler entirely.
  RETRAIN_SCHEDULE_HOUR_UTC — hour (0-23 UTC) at which to run (default: 3)

The scheduler runs in a daemon asyncio task so it never blocks the server.
If a retrain is already running when the schedule fires, the tick is skipped.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

log = logging.getLogger("noctra.scheduler")

_task: asyncio.Task | None = None


async def _scheduler_loop(interval_hours: int, target_hour_utc: int) -> None:
    log.info(
        "Retrain scheduler started — interval=%dh, target_hour=%02d:00 UTC",
        interval_hours, target_hour_utc,
    )
    while True:
        now = datetime.now(timezone.utc)
        # Calculate seconds until next target_hour_utc
        next_hour = now.replace(hour=target_hour_utc, minute=0, second=0, microsecond=0)
        if next_hour <= now:
            # Already past today's window — aim for tomorrow
            from datetime import timedelta
            next_hour = next_hour + timedelta(days=1)

        wait_secs = (next_hour - now).total_seconds()
        log.info("Retrain scheduler: next run in %.1f hours (at %s UTC)",
                 wait_secs / 3600, next_hour.strftime("%Y-%m-%d %H:%M"))

        await asyncio.sleep(wait_secs)

        # Import here to avoid circular imports at module level
        from engine.retrain_orchestrator import get_status, start_retrain
        status = get_status()
        if status["running"]:
            log.info("Retrain scheduler: skipping tick — pipeline already running")
        else:
            log.info("Retrain scheduler: triggering scheduled retrain …")
            try:
                await start_retrain(background=True)
            except Exception as exc:
                log.exception("Scheduled retrain failed to start: %s", exc)

        # After the run fires, sleep the full interval before recalculating
        if interval_hours > 0:
            await asyncio.sleep(interval_hours * 3600)
        else:
            break  # interval=0 means run once then stop


def start_scheduler(interval_hours: int = 24, target_hour_utc: int = 3) -> None:
    """
    Start the background scheduler task.
    Call this inside the FastAPI lifespan after the event loop is running.
    """
    global _task
    if interval_hours <= 0:
        log.info("Retrain scheduler disabled (RETRAIN_SCHEDULE_HOURS=0)")
        return
    if _task and not _task.done():
        log.warning("Retrain scheduler already running — skipping duplicate start")
        return
    _task = asyncio.create_task(
        _scheduler_loop(interval_hours, target_hour_utc),
        name="retrain_scheduler",
    )
    log.info("Retrain scheduler task created")


def stop_scheduler() -> None:
    """Cancel the scheduler task gracefully at shutdown."""
    global _task
    if _task and not _task.done():
        _task.cancel()
        log.info("Retrain scheduler stopped")
    _task = None
