"""
engine/retrain_orchestrator.py
===============================
Orchestrates the full ML-driven self-upgrade cycle for Noctra.

Phases run in sequence:
  1. corpus_analyser.py      — analyse training_corpus.ndjson → rule_insights.json
  2. rule_synthesiser.py     — patch rule_config.json with optimised thresholds
  3. parser_pattern_extractor.py — update parser_hints.json with field aliases
  4. train_model.py          — retrain XGBoost; gate on AUC ≥ 0.80 before swap

Each phase runs as a subprocess so the FastAPI event loop stays responsive.
Progress and results are stored in a shared in-RAM status dict that the
/admin/retrain endpoint polls.

Call start_retrain() from the router; it is idempotent (rejects concurrent runs).
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("noctra.retrain")

_PIPELINE_ROOT = Path(__file__).parent.parent.parent / "noctra_training_data"

_PHASES = [
    {
        "id": 2,
        "name": "corpus_analyser",
        "script": _PIPELINE_ROOT / "corpus_analyser.py",
        "description": "Analyse training corpus → rule_insights.json",
    },
    {
        "id": 3,
        "name": "rule_synthesiser",
        "script": _PIPELINE_ROOT / "rule_synthesiser.py",
        "description": "Synthesise rule threshold & pattern updates → rule_config.json",
    },
    {
        "id": 4,
        "name": "parser_pattern_extractor",
        "script": _PIPELINE_ROOT / "parser_pattern_extractor.py",
        "description": "Extract parser field aliases → parser_hints.json",
    },
    {
        "id": 5,
        "name": "train_model",
        "script": _PIPELINE_ROOT / "train_model.py",
        "description": "Retrain ML classifier; gate on AUC ≥ 0.80 before model swap",
    },
]

# Shared state — one retrain at a time
_status: dict[str, Any] = {
    "running": False,
    "phase": None,
    "progress_pct": 0,
    "started_at": None,
    "finished_at": None,
    "outcome": None,   # "success" | "failed" | None
    "error": None,
    "phase_results": [],
    "changes": [],
}

_lock = asyncio.Lock()


def get_status() -> dict:
    return dict(_status)


async def start_retrain(background: bool = True) -> dict:
    """
    Launch the retrain pipeline.
    Returns immediately with {"queued": true} if background=True,
    or blocks until done if background=False (for testing).
    """
    async with _lock:
        if _status["running"]:
            return {"queued": False, "reason": "A retrain is already running"}

        _status.update(
            running=True,
            phase=None,
            progress_pct=0,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            outcome=None,
            error=None,
            phase_results=[],
            changes=[],
        )

    if background:
        asyncio.create_task(_run_pipeline())
        return {"queued": True, "started_at": _status["started_at"]}
    else:
        await _run_pipeline()
        return get_status()


async def _run_pipeline() -> None:
    """Run all phases sequentially; update _status throughout."""
    log.info("Retrain pipeline starting …")
    n = len(_PHASES)
    try:
        for i, phase in enumerate(_PHASES):
            _status["phase"] = phase["name"]
            _status["progress_pct"] = int((i / n) * 100)
            log.info("[%d/%d] %s …", i + 1, n, phase["description"])

            t0 = time.monotonic()
            ok, stdout, stderr = await _run_script(phase["script"])
            elapsed = round(time.monotonic() - t0, 1)

            phase_result = {
                "phase_id": phase["id"],
                "name": phase["name"],
                "description": phase["description"],
                "success": ok,
                "elapsed_seconds": elapsed,
                "stdout_tail": stdout[-2000:] if stdout else "",
                "stderr_tail": stderr[-500:] if stderr else "",
            }
            _status["phase_results"].append(phase_result)

            if not ok:
                raise RuntimeError(
                    f"Phase {phase['name']} failed (exit non-zero). "
                    f"stderr: {stderr[-400:]}"
                )

        # Extract what changed from the last rule_synthesiser output
        _status["changes"] = _read_synthesis_changes()
        _status["progress_pct"] = 100
        _status["outcome"] = "success"
        log.info("Retrain pipeline completed successfully.")

    except Exception as exc:
        log.exception("Retrain pipeline failed: %s", exc)
        _status["outcome"] = "failed"
        _status["error"] = str(exc)

    finally:
        _status["running"] = False
        _status["phase"] = None
        _status["finished_at"] = datetime.now(timezone.utc).isoformat()


async def _run_script(script_path: Path) -> tuple[bool, str, str]:
    """Run a Python script in a subprocess; return (ok, stdout, stderr)."""
    if not script_path.exists():
        return False, "", f"Script not found: {script_path}"
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(script_path.parent),
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=600)
        ok = proc.returncode == 0
        return ok, stdout_b.decode("utf-8", errors="replace"), stderr_b.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return False, "", "Script timed out after 600 seconds"
    except Exception as exc:
        return False, "", str(exc)


def _read_synthesis_changes() -> list[dict]:
    """Load the changes list from the last synthesis_report.json."""
    report_path = _PIPELINE_ROOT / "synthesis_report.json"
    try:
        import json
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return data.get("changes", [])
    except Exception:
        return []
