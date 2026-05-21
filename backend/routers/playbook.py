"""
routers/playbook.py
===================
Static response playbooks loaded from JSON files in data/playbooks/.

    GET /playbook/{rule_id}
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/playbook", tags=["playbook"])

_PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "data" / "playbooks"


@router.get("/{rule_id}")
async def get_playbook(rule_id: str) -> dict:
    # Try the rule-specific file first; fall back to default.
    candidate = _PLAYBOOK_DIR / f"{rule_id.upper()}.json"
    if not candidate.exists():
        candidate = _PLAYBOOK_DIR / "default.json"
    if not candidate.exists():
        raise HTTPException(500, "Playbook directory is missing default.json")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(500, f"Playbook {candidate.name} is invalid JSON: {exc}") from exc
