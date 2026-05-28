"""
engine/demo_data.py
===================
Synthetic multi-stage attack used by POST /ingest/demo.

The point of the demo is that EVERY page works against a real backend
session — Hunt, Rules, Threat Intel, the AI agent, chains. So instead of a
client-only stub we generate a realistic dataset that fires a full kill
chain from one attacker, then push it through the exact same ingest
pipeline a real upload uses.

Scenario (single attacker 203.0.113.66 → target 10.0.0.x):
  Recon (R008) → Brute force w/ compromise (R001) → Privilege escalation
  (R003) → Lateral movement (R004) → Data exfiltration (R005), plus a port
  scan (R002) and benign noise for UEBA / hunt realism.
"""

from __future__ import annotations

from datetime import datetime, timedelta

ATTACKER = "203.0.113.66"
TARGET = "10.0.0.10"
EXFIL_DEST = "45.137.21.9"

_HEADER = "timestamp,source_ip,dest_ip,event_type,user,status,bytes,port"


def _ts(base: datetime, **delta) -> str:
    return (base + timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")


def build_demo_csv() -> bytes:
    """Return a CSV byte blob the normal parser/pipeline can ingest."""
    base = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)
    rows: list[str] = [_HEADER]

    # --- Benign baseline noise (UEBA / hunt realism) ----------------------
    for i in range(20):
        rows.append(
            f"{_ts(base, minutes=-120, seconds=i*3)},10.0.0.{50+i%5},"
            f"{TARGET},login,jdoe,SUCCESS,1200,443"
        )

    # --- Stage 1: Web recon / fuzzing — 25x HTTP 404 (R008) ---------------
    for i in range(25):
        rows.append(
            f"{_ts(base, seconds=i*2)},{ATTACKER},{TARGET},http,,404,0,80"
        )

    # --- Stage 2: Brute force, 8 fails in <60s then SUCCESS (R001) --------
    for i in range(8):
        rows.append(
            f"{_ts(base, minutes=5, seconds=i*5)},{ATTACKER},{TARGET},"
            f"login,admin,FAILED,0,22"
        )
    rows.append(
        f"{_ts(base, minutes=5, seconds=50)},{ATTACKER},{TARGET},"
        f"login,admin,SUCCESS,0,22"
    )

    # --- Stage 3: Privilege escalation — normal then admin (R003) --------
    rows.append(
        f"{_ts(base, minutes=8)},{ATTACKER},{TARGET},login,jdoe,SUCCESS,0,22"
    )
    rows.append(
        f"{_ts(base, minutes=8, seconds=40)},{ATTACKER},{TARGET},"
        f"login,admin,SUCCESS,0,22"
    )

    # --- Stage 4: Lateral movement — admin on 3+ hosts in 5m (R004) -----
    for h in range(5, 9):
        rows.append(
            f"{_ts(base, minutes=10, seconds=(h-5)*30)},{ATTACKER},"
            f"10.0.0.{h},login,admin,SUCCESS,0,22"
        )

    # --- Stage 5: Data exfiltration — >100MB to external IP (R005) ------
    rows.append(
        f"{_ts(base, minutes=15)},{ATTACKER},{EXFIL_DEST},"
        f"transfer,admin,SUCCESS,524288000,443"
    )

    # --- Stage 6: Port scan — 14 distinct ports in 30s (R002) -----------
    for i, port in enumerate(
        [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    ):
        rows.append(
            f"{_ts(base, minutes=20, seconds=i)},{ATTACKER},{TARGET},"
            f"scan,,FAILED,0,{port}"
        )

    return ("\n".join(rows)).encode("utf-8")
