"""
routers/threatintel.py
======================
Enrich a single IP using AbuseIPDB + VirusTotal in parallel.

    GET /threatintel/{session_id}/{ip}

Both vendors are called concurrently via httpx.AsyncClient.
The merged result is cached on the session (session.intel_cache) so the
analyst can reopen the same alert without burning the daily free-tier quota.

Cache key: lowercased IP. Cleared automatically when the session expires.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any, Dict

import httpx
from fastapi import APIRouter, HTTPException

from config import settings
from session.store import session_store

log = logging.getLogger("noctra.threatintel")

router = APIRouter(prefix="/threatintel", tags=["threatintel"])

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_HTTP_TIMEOUT = 15  # seconds — both APIs are usually <2s


# ---------------------------------------------------------------------------
# Vendor adapters
# ---------------------------------------------------------------------------
async def _query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not settings.abuseipdb_ready:
        return {"available": False, "reason": "API key not configured"}
    try:
        r = await client.get(
            _ABUSEIPDB_URL,
            headers={"Accept": "application/json", "Key": settings.abuseipdb_api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        r.raise_for_status()
        body = r.json().get("data", {})
        return {
            "available": True,
            "abuse_confidence_score": body.get("abuseConfidenceScore"),
            "country_code": body.get("countryCode"),
            "isp": body.get("isp"),
            "domain": body.get("domain"),
            "usage_type": body.get("usageType"),
            "total_reports": body.get("totalReports"),
            "last_reported_at": body.get("lastReportedAt"),
            "is_whitelisted": body.get("isWhitelisted"),
            "is_public": body.get("isPublic"),
        }
    except httpx.HTTPError as exc:
        log.warning("AbuseIPDB call failed for %s: %s", ip, exc)
        return {"available": False, "reason": f"AbuseIPDB error: {exc}"}


async def _query_virustotal(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not settings.virustotal_ready:
        return {"available": False, "reason": "API key not configured"}
    try:
        r = await client.get(
            _VT_URL.format(ip=ip),
            headers={"x-apikey": settings.virustotal_api_key},
        )
        if r.status_code == 404:
            return {"available": True, "stats": {}, "reputation": 0, "country": None,
                    "asn": None, "as_owner": None, "note": "IP not yet seen by VT"}
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "reputation": attrs.get("reputation"),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "network": attrs.get("network"),
            "stats": {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
    except httpx.HTTPError as exc:
        log.warning("VirusTotal call failed for %s: %s", ip, exc)
        return {"available": False, "reason": f"VirusTotal error: {exc}"}


# ---------------------------------------------------------------------------
# Verdict derived from the merged data
# ---------------------------------------------------------------------------
def _derive_verdict(abuse: Dict[str, Any], vt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine the two scores into a single human-readable verdict.

    AbuseIPDB confidence is 0-100; VirusTotal `malicious` is a vendor count.
    We classify into: clean | suspicious | malicious.
    """
    score = 0
    rationale = []

    if abuse.get("available"):
        conf = abuse.get("abuse_confidence_score") or 0
        if conf >= 75:
            score += 50
            rationale.append(f"AbuseIPDB confidence {conf}/100")
        elif conf >= 25:
            score += 20
            rationale.append(f"AbuseIPDB confidence {conf}/100")

    if vt.get("available"):
        mal = (vt.get("stats") or {}).get("malicious", 0)
        sus = (vt.get("stats") or {}).get("suspicious", 0)
        if mal >= 3:
            score += 50
            rationale.append(f"{mal} VirusTotal vendors flagged malicious")
        elif mal >= 1 or sus >= 3:
            score += 25
            rationale.append(f"{mal} malicious / {sus} suspicious on VirusTotal")

    if score >= 50:
        label = "malicious"
    elif score >= 20:
        label = "suspicious"
    else:
        label = "clean"
    return {"label": label, "score": score, "rationale": rationale}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@router.get("/{session_id}/{ip}")
async def threatintel(session_id: str, ip: str) -> dict:
    sess = session_store.get(session_id)
    if sess is None:
        raise HTTPException(404, "Session not found or already expired")

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"{ip!r} is not a valid IP address")

    cache_key = ip.lower()
    cached = sess.intel_cache.get(cache_key)
    if cached:
        return {**cached, "_cache_hit": True}

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        abuse, vt = await asyncio.gather(
            _query_abuseipdb(client, ip),
            _query_virustotal(client, ip),
        )

    verdict = _derive_verdict(abuse, vt)
    result = {
        "ip": ip,
        "abuseipdb": abuse,
        "virustotal": vt,
        "verdict": verdict,
        "_cache_hit": False,
    }
    sess.intel_cache[cache_key] = {k: v for k, v in result.items() if k != "_cache_hit"}
    return result
