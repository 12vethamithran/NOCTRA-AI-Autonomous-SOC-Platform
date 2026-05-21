"""
engine/enrichment.py
====================
Local IOC extraction + timeline helpers used by the /investigate router.
No external API calls happen here — threat intel lives in routers/threatintel.py.
"""

from __future__ import annotations

import re
from typing import Dict, List

import pandas as pd


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def extract_iocs(rows: pd.DataFrame) -> Dict[str, List[str]]:
    """Pull IPs / users / ports / domains / hashes out of the supplied rows."""
    if rows.empty:
        return {"ips": [], "users": [], "ports": [], "domains": [], "hashes": []}

    ips: set[str] = set()
    for col in ("source_ip", "dest_ip"):
        if col in rows.columns:
            ips.update(str(x) for x in rows[col].dropna().tolist() if str(x))
    # Sweep the raw column for anything embedded in messages.
    if "raw" in rows.columns:
        for line in rows["raw"].dropna().astype(str):
            ips.update(_IP_RE.findall(line))

    users = sorted({str(u) for u in rows.get("user", pd.Series([], dtype=object)).dropna()})
    ports = sorted({int(p) for p in rows.get("port", pd.Series([], dtype="Int64")).dropna()})
    domains = sorted(
        {m for line in rows.get("raw", pd.Series([], dtype=object)).dropna().astype(str)
         for m in _DOMAIN_RE.findall(line)
         if not _IP_RE.fullmatch(m)}
    )
    hashes = sorted(
        {m for line in rows.get("raw", pd.Series([], dtype=object)).dropna().astype(str)
         for m in _HASH_RE.findall(line)}
    )
    return {
        "ips": sorted(ips),
        "users": users,
        "ports": [str(p) for p in ports],
        "domains": domains,
        "hashes": hashes,
    }


def build_timeline(rows: pd.DataFrame) -> List[dict]:
    """Turn raw log rows into a frontend-friendly timeline list."""
    if rows.empty:
        return []
    rows = rows.sort_values("timestamp", na_position="last")
    out: List[dict] = []
    for idx, row in rows.iterrows():
        status = str(row.get("status") or "").upper()
        # Tone for the UI badge.
        if status in {"FAILED", "401", "403", "404", "500"}:
            tone = "suspicious"
        elif status in {"SUCCESS", "200", "201", "204"}:
            tone = "normal"
        else:
            tone = "info"
        ts = row.get("timestamp")
        out.append({
            "row_index": int(idx),
            "timestamp": ts.isoformat() if pd.notna(ts) else None,
            "source_ip": row.get("source_ip"),
            "dest_ip": row.get("dest_ip"),
            "event_type": row.get("event_type"),
            "user": row.get("user"),
            "status": row.get("status"),
            "port": int(row["port"]) if pd.notna(row.get("port")) else None,
            "tone": tone,
            "raw": row.get("raw"),
        })
    return out


def entity_summaries(rows: pd.DataFrame) -> Dict[str, List[dict]]:
    """Per-entity quick-look cards (IPs, users, hosts)."""
    cards: Dict[str, List[dict]] = {"ips": [], "users": [], "hosts": []}
    if rows.empty:
        return cards

    # IPs: combine source + dest counts.
    ip_seen: Dict[str, dict] = {}
    for col, role in (("source_ip", "source"), ("dest_ip", "dest")):
        if col not in rows.columns:
            continue
        for ip, group in rows[rows[col].notna()].groupby(col):
            entry = ip_seen.setdefault(str(ip), {"ip": str(ip), "events": 0, "roles": set(),
                                                  "first_seen": None, "last_seen": None})
            entry["events"] += len(group)
            entry["roles"].add(role)
            ts_min, ts_max = group["timestamp"].min(), group["timestamp"].max()
            entry["first_seen"] = min(filter(pd.notna, [entry["first_seen"], ts_min]), default=None)
            entry["last_seen"]  = max(filter(pd.notna, [entry["last_seen"],  ts_max]), default=None)
    for e in ip_seen.values():
        e["roles"] = sorted(e["roles"])
        e["first_seen"] = e["first_seen"].isoformat() if e["first_seen"] is not None and pd.notna(e["first_seen"]) else None
        e["last_seen"]  = e["last_seen"].isoformat()  if e["last_seen"]  is not None and pd.notna(e["last_seen"])  else None
    cards["ips"] = sorted(ip_seen.values(), key=lambda x: -x["events"])

    # Users
    if "user" in rows.columns:
        for user, group in rows[rows["user"].notna()].groupby("user"):
            failures = int((group["status"].astype(str).str.upper() == "FAILED").sum()) if "status" in group else 0
            cards["users"].append({
                "user": str(user),
                "events": len(group),
                "failures": failures,
            })
        cards["users"].sort(key=lambda x: -x["events"])

    # Hosts (dest_ip used as host proxy)
    if "dest_ip" in rows.columns:
        cards["hosts"] = [
            {"host": str(h), "events": int(c)}
            for h, c in rows["dest_ip"].dropna().value_counts().items()
        ]

    return cards
