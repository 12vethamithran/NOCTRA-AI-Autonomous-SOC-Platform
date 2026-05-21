"""
engine/parser.py
================
Turn an uploaded log file into a normalised Pandas DataFrame.

Supported formats (phase 1):
    1. CSV                — `.csv` with a header row
    2. JSON / JSONL       — either an array of objects, or one object per line
    3. Apache / Nginx     — common access log format (combined or common)
    4. Syslog             — RFC3164-ish `Mon DD HH:MM:SS host proc[pid]: msg`
    5. Windows Event CSV  — `TimeCreated,EventID,Computer,User,Message`

Normalised schema (every parser produces these columns):
    timestamp     : datetime64[ns, UTC]
    source_ip     : str | None
    dest_ip       : str | None
    event_type    : str
    user          : str | None
    status        : str | None
    bytes         : Int64 | None
    port          : Int64 | None
    raw           : str   (the original line / JSON object, for the timeline)

The parser is intentionally tolerant: unknown columns are kept in `raw`,
malformed lines are dropped with a warning rather than crashing the whole upload.
"""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


# -----------------------------------------------------------------------------
# Output contract
# -----------------------------------------------------------------------------
NORMALISED_COLUMNS: List[str] = [
    "timestamp",
    "source_ip",
    "dest_ip",
    "event_type",
    "user",
    "status",
    "bytes",
    "port",
    "raw",
]


@dataclass
class ParseResult:
    """What the parser returns to the ingest router."""

    dataframe: pd.DataFrame
    detected_format: str          # one of: csv | json | apache | syslog | winevent
    event_count: int
    dropped_lines: int            # malformed rows we skipped


# -----------------------------------------------------------------------------
# Top-level dispatcher
# -----------------------------------------------------------------------------
def parse(filename: str, content: bytes) -> ParseResult:
    """
    Auto-detect the log format and dispatch to the right parser.

    `filename` is used as a hint (extension), `content` is the raw upload bytes.
    """
    text = _decode(content)
    fmt = _detect_format(filename, text)

    if fmt == "csv":
        df, dropped = _parse_csv(text)
    elif fmt == "json":
        df, dropped = _parse_json(text)
    elif fmt == "apache":
        df, dropped = _parse_apache(text)
    elif fmt == "syslog":
        df, dropped = _parse_syslog(text)
    elif fmt == "winevent":
        df, dropped = _parse_winevent_csv(text)
    else:
        raise ValueError(f"Unsupported log format: {fmt!r}")

    df = _finalise(df)

    return ParseResult(
        dataframe=df,
        detected_format=fmt,
        event_count=len(df),
        dropped_lines=dropped,
    )


# -----------------------------------------------------------------------------
# Decoding & format detection
# -----------------------------------------------------------------------------
def _decode(content: bytes) -> str:
    """Decode upload bytes leniently — replace bad bytes rather than crash."""
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def _detect_format(filename: str, text: str) -> str:
    """Best-effort format detection by extension first, then content sniffing."""
    name = filename.lower()
    if name.endswith(".csv"):
        # Windows Event CSV looks like normal CSV but has a fixed header.
        first_line = text.splitlines()[0] if text else ""
        if "EventID" in first_line and "TimeCreated" in first_line:
            return "winevent"
        return "csv"
    if name.endswith((".json", ".jsonl", ".ndjson")):
        return "json"
    if name.endswith(".log") or name.endswith(".txt"):
        # Disambiguate apache vs syslog via regex.
        sample = "\n".join(text.splitlines()[:5])
        if _APACHE_RE.search(sample):
            return "apache"
        if _SYSLOG_RE.search(sample):
            return "syslog"
        # Plain text fallback — treat as syslog (most permissive).
        return "syslog"

    # No extension match — sniff the content.
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    if "," in (text.splitlines()[0] if text else ""):
        return "csv"
    if _APACHE_RE.search(text[:2000]):
        return "apache"
    return "syslog"


# -----------------------------------------------------------------------------
# CSV
# -----------------------------------------------------------------------------
# Map common alternate column names → our normalised names.
_CSV_COLUMN_ALIASES: Dict[str, str] = {
    "time": "timestamp",
    "datetime": "timestamp",
    "date": "timestamp",
    "@timestamp": "timestamp",
    "src_ip": "source_ip",
    "src": "source_ip",
    "client_ip": "source_ip",
    "dst_ip": "dest_ip",
    "dst": "dest_ip",
    "destination_ip": "dest_ip",
    "event": "event_type",
    "action": "event_type",
    "username": "user",
    "account": "user",
    "result": "status",
    "outcome": "status",
    "size": "bytes",
    "length": "bytes",
    "dest_port": "port",
    "dst_port": "port",
}


def _parse_csv(text: str) -> Tuple[pd.DataFrame, int]:
    """Generic CSV with header row. Aliased columns are renamed; extras kept in raw."""
    df = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
    # Normalise column names: lower-case, strip whitespace, apply aliases.
    df.columns = [c.strip() for c in df.columns]
    rename_map = {c: _CSV_COLUMN_ALIASES.get(c.lower(), c.lower()) for c in df.columns}
    df = df.rename(columns=rename_map)

    # Build the `raw` column from the original row (joined back to CSV).
    df["raw"] = df.astype(str).agg(",".join, axis=1)
    return df, 0


# -----------------------------------------------------------------------------
# JSON / JSONL
# -----------------------------------------------------------------------------
def _parse_json(text: str) -> Tuple[pd.DataFrame, int]:
    """Accept either a JSON array OR newline-delimited JSON objects."""
    text = text.strip()
    rows: List[Dict[str, Any]] = []
    dropped = 0

    if text.startswith("["):
        # Single JSON array.
        try:
            rows = json.loads(text)
            if not isinstance(rows, list):
                raise ValueError("JSON root is not an array")
        except json.JSONDecodeError:
            return pd.DataFrame(columns=NORMALISED_COLUMNS), 1
    else:
        # Newline-delimited JSON.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                dropped += 1

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=NORMALISED_COLUMNS), dropped

    df.columns = [str(c).strip().lower() for c in df.columns]
    df = df.rename(columns={k: v for k, v in _CSV_COLUMN_ALIASES.items() if k in df.columns})
    df["raw"] = df.apply(lambda r: json.dumps(r.dropna().to_dict(), default=str), axis=1)
    return df, dropped


# -----------------------------------------------------------------------------
# Apache / Nginx combined access log
#   203.0.113.42 - - [15/Jan/2024:14:02:01 +0000] "GET /admin HTTP/1.1" 401 512
# -----------------------------------------------------------------------------
_APACHE_RE = re.compile(
    r'^(?P<source_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
)


def _parse_apache(text: str) -> Tuple[pd.DataFrame, int]:
    rows: List[Dict[str, Any]] = []
    dropped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _APACHE_RE.match(line)
        if not m:
            dropped += 1
            continue
        ts = _try_parse_apache_ts(m.group("ts"))
        rows.append(
            {
                "timestamp": ts,
                "source_ip": m.group("source_ip"),
                "user": None if m.group("user") == "-" else m.group("user"),
                "event_type": f"http_{m.group('method').lower()}",
                "status": m.group("status"),
                "bytes": None if m.group("bytes") == "-" else m.group("bytes"),
                "port": None,
                "dest_ip": None,
                "raw": line,
            }
        )
    return pd.DataFrame(rows), dropped


def _try_parse_apache_ts(s: str) -> Optional[datetime]:
    # 15/Jan/2024:14:02:01 +0000
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


# -----------------------------------------------------------------------------
# Syslog (RFC3164-ish)
#   Jan 15 14:02:01 server01 sshd[1234]: Failed password for admin from 203.0.113.42
# -----------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$'
)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _parse_syslog(text: str) -> Tuple[pd.DataFrame, int]:
    rows: List[Dict[str, Any]] = []
    dropped = 0
    current_year = datetime.now(timezone.utc).year
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _SYSLOG_RE.match(line)
        if not m:
            dropped += 1
            continue
        ts = _try_parse_syslog_ts(m.group("ts"), current_year)
        msg = m.group("msg")
        # Extract first IP from the message (best effort).
        ip_match = _IP_RE.search(msg)
        # Status heuristic: words like Failed / Accepted / Invalid in sshd messages.
        status: Optional[str] = None
        lower = msg.lower()
        if "failed" in lower or "invalid" in lower:
            status = "FAILED"
        elif "accepted" in lower or "success" in lower:
            status = "SUCCESS"

        # User heuristic: "for <user>" or "user <user>".
        user_match = re.search(r"\b(?:for|user)\s+(\S+)", msg)
        rows.append(
            {
                "timestamp": ts,
                "source_ip": ip_match.group(0) if ip_match else None,
                "dest_ip": None,
                "event_type": m.group("proc"),
                "user": user_match.group(1) if user_match else None,
                "status": status,
                "bytes": None,
                "port": None,
                "raw": line,
            }
        )
    return pd.DataFrame(rows), dropped


def _try_parse_syslog_ts(s: str, year: int) -> Optional[datetime]:
    try:
        return datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


# -----------------------------------------------------------------------------
# Windows Event CSV export
# -----------------------------------------------------------------------------
def _parse_winevent_csv(text: str) -> Tuple[pd.DataFrame, int]:
    df = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
    df.columns = [c.strip() for c in df.columns]

    # Map Windows fields → our schema.
    rename = {
        "TimeCreated": "timestamp",
        "EventID": "event_type",
        "Computer": "dest_ip",   # store host in dest_ip for now (no separate host col yet)
        "User": "user",
        "Message": "raw",
    }
    df = df.rename(columns={k: v for k, v in rename.items() if k in df.columns})

    # Status heuristic: failed logon events.
    if "event_type" in df.columns:
        df["status"] = df["event_type"].map(
            lambda e: "FAILED" if str(e) in {"4625", "529", "530"} else "SUCCESS"
        )
    df["source_ip"] = None
    df["bytes"] = None
    df["port"] = None
    if "raw" not in df.columns:
        df["raw"] = df.astype(str).agg(",".join, axis=1)
    return df, 0


# -----------------------------------------------------------------------------
# Finalisation — coerce types, fill missing columns, drop bad timestamps
# -----------------------------------------------------------------------------
def _finalise(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure every normalised column exists and has the right dtype."""
    if df.empty:
        return pd.DataFrame(columns=NORMALISED_COLUMNS)

    # Add any missing columns as None.
    for col in NORMALISED_COLUMNS:
        if col not in df.columns:
            df[col] = None

    # Parse timestamps (already-parsed datetimes pass through unchanged).
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Cast numerics safely (empty strings → NaN → nullable Int64).
    for num_col in ("bytes", "port"):
        df[num_col] = pd.to_numeric(df[num_col], errors="coerce").astype("Int64")

    # Empty strings → None for string columns (cleaner downstream).
    for str_col in ("source_ip", "dest_ip", "event_type", "user", "status"):
        df[str_col] = df[str_col].replace({"": None})

    # Keep only the normalised columns in a known order, plus anything extra
    # the source provided (handy for L2 investigation).
    extra_cols = [c for c in df.columns if c not in NORMALISED_COLUMNS]
    return df[NORMALISED_COLUMNS + extra_cols]
