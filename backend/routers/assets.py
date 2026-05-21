"""
routers/assets.py
=================
Asset inventory management — upload asset CSV for criticality-based risk scoring.

POST /assets/{session_id} — upload asset CSV
GET /assets/{session_id} — get asset database
POST /enrich-assets/{session_id} — attach asset context to alerts
"""

import io
from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, UploadFile

from session.store import session_store

router = APIRouter(tags=["assets"])

# Asset CSV columns expected
ASSET_COLUMNS = {
    "ip",
    "hostname",
    "criticality",
    "os",
    "last_patched",
    "owner",
    "department",
}

# Criticality multipliers for risk scoring
CRITICALITY_MULTIPLIERS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.2,
    "low": 1.0,
}


@router.post("/assets/{session_id}")
async def upload_assets(session_id: str, file: UploadFile = File(...)):
    """
    Upload an asset inventory CSV.
    Expected columns: ip, hostname, criticality, os, last_patched, owner, department
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=415, detail="Only CSV files accepted")

    try:
        import csv

        content = await file.read()
        text = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))

        assets = []
        for row in reader:
            if not row.get("ip"):
                continue

            assets.append(
                {
                    "ip": row.get("ip", ""),
                    "hostname": row.get("hostname", ""),
                    "criticality": row.get("criticality", "medium").lower(),
                    "os": row.get("os", ""),
                    "last_patched": row.get("last_patched", ""),
                    "owner": row.get("owner", ""),
                    "department": row.get("department", ""),
                }
            )

        sess.asset_db = assets
        return {"asset_count": len(assets), "assets": assets}

    except Exception as e:
        raise HTTPException(status_code=422, detail=f"CSV parsing failed: {str(e)}")


@router.get("/assets/{session_id}")
async def get_assets(session_id: str):
    """
    Get the asset database for this session.
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "asset_count": len(sess.asset_db),
        "assets": sess.asset_db,
    }


@router.post("/enrich-assets/{session_id}")
async def enrich_alerts_with_assets(session_id: str):
    """
    Enrich existing alerts with asset context and adjust risk scores.

    For each alert whose source_ip or dest_ip matches an asset:
    - Attach asset_context dict
    - Recompute risk_score = tp_probability × criticality_multiplier
    """
    sess = session_store.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if not sess.asset_db:
        return {"enriched_count": 0, "alerts": sess.alerts}

    # Build IP -> asset lookup
    ip_to_asset: Dict[str, Dict[str, Any]] = {}
    for asset in sess.asset_db:
        ip_to_asset[asset["ip"]] = asset

    # Enrich alerts
    enriched_count = 0

    for alert in sess.alerts:
        source_ip = alert.get("source_ip")
        dest_ip = alert.get("dest_ip")

        # Check source IP
        if source_ip and source_ip in ip_to_asset:
            asset = ip_to_asset[source_ip]
            alert["asset_context"] = asset
            mult = CRITICALITY_MULTIPLIERS.get(asset.get("criticality", "medium"), 1.0)
            base_prob = alert.get("tp_probability", 0.5) or 0.5
            alert["risk_score"] = min(2.0, base_prob * mult)
            enriched_count += 1

        # Check dest IP
        elif dest_ip and dest_ip in ip_to_asset:
            asset = ip_to_asset[dest_ip]
            alert["asset_context"] = asset
            mult = CRITICALITY_MULTIPLIERS.get(asset.get("criticality", "medium"), 1.0)
            base_prob = alert.get("tp_probability", 0.5) or 0.5
            alert["risk_score"] = min(2.0, base_prob * mult)
            enriched_count += 1

    return {"enriched_count": enriched_count, "alerts": sess.alerts}
