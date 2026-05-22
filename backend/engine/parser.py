"""
engine/parser.py
================
Turn an uploaded log file into a normalised Pandas DataFrame.

Design goal: **never fail.** Any text-based input must produce a usable
DataFrame. Whatever the format, the parser either understands it or falls back
to a generic line-by-line parser that treats every line as an event and
heuristically extracts a timestamp / IP / user. The only way to get zero
events is a genuinely empty upload.

Supported formats:
    1. CSV / TSV / delimited — auto-detects the delimiter (`,`  `\\t`  `;`  `|`)
    2. JSON / JSONL / NDJSON — array, single object, wrapper object, or
                               one object per line
    3. Apache / Nginx        — common / combined access log
    4. Syslog                — RFC3164-ish `Mon DD HH:MM:SS host proc[pid]: msg`
    5. Windows Event CSV     — `TimeCreated,EventID,Computer,User,Message`
    6. logfmt / key=value    — `ts=... level=info src=1.2.3.4 msg="..."`
    7. generic               — ANY other text; one event per line (fallback)

Normalised schema (every parser produces these columns):
    timestamp     : datetime64[ns, UTC]
    source_ip     : str | None
    dest_ip       : str | None
    event_type    : str | None
    user          : str | None
    status        : str | None
    bytes         : Int64 | None
    port          : Int64 | None
    raw           : str   (the original line / JSON object, for the timeline)

The parser is intentionally tolerant: unknown columns are kept (handy for L2
investigation), malformed lines are skipped rather than crashing the upload,
and a crashing sub-parser silently degrades to the generic parser.
"""

from __future__ import annotations

import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

log = logging.getLogger("noctra.parser")


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
    detected_format: str          # csv | json | apache | syslog | winevent | logfmt | generic
    event_count: int
    dropped_lines: int            # malformed rows we skipped


# -----------------------------------------------------------------------------
# Top-level dispatcher
# -----------------------------------------------------------------------------
def parse(filename: str, content: bytes) -> ParseResult:
    """
    Auto-detect the log format and dispatch to the right parser.

    `filename` is used as a hint (extension), `content` is the raw upload bytes.
    Guarantees: never raises for non-empty text — degrades to the generic
    line parser if the detected format's parser crashes or yields nothing.
    """
    text = _decode(content)
    try:
        fmt = _detect_format(filename, text)
    except Exception as exc:  # noqa: BLE001 — detection must never kill ingest
        log.warning("Format detection crashed on %s (%s); using generic", filename, exc)
        fmt = "generic"

    parser = _PARSERS.get(fmt, _parse_generic)
    df: pd.DataFrame
    dropped = 0
    try:
        df, dropped = parser(text)
    except Exception as exc:  # noqa: BLE001 — a bad parser must never kill ingest
        log.warning("Parser %r crashed on %s (%s); falling back to generic", fmt, filename, exc)
        df = pd.DataFrame()

    # Fallback: detected format produced nothing usable → treat every line as
    # an event. This is what makes "any input" work.
    if (df is None or df.empty) and fmt != "generic" and text.strip():
        try:
            df, dropped = _parse_generic(text)
            fmt = "generic"
            log.info("Generic fallback engaged for %s", filename)
        except Exception as exc:  # noqa: BLE001
            log.warning("Generic fallback crashed on %s (%s)", filename, exc)
            df = pd.DataFrame(columns=NORMALISED_COLUMNS)

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
    if not content:
        return ""
    # Strip a UTF-8/UTF-16 BOM if present.
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if content.startswith(bom):
            try:
                return content.decode(enc)
            except UnicodeDecodeError:
                break
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def _detect_format(filename: str, text: str) -> str:
    """Best-effort format detection by extension first, then content sniffing."""
    name = (filename or "").lower()
    sample_lines = [ln for ln in text.splitlines() if ln.strip()][:8]
    first_line = sample_lines[0] if sample_lines else ""

    # --- Extension hints ---------------------------------------------------
    if name.endswith((".json", ".jsonl", ".ndjson")):
        return "json"
    if name.endswith((".csv", ".tsv")):
        if "EventID" in first_line and "TimeCreated" in first_line:
            return "winevent"
        return "csv"

    # --- Content sniffing (works for .log/.txt and extensionless files) ----
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    if "EventID" in first_line and "TimeCreated" in first_line:
        return "winevent"

    # Apache / syslog: a majority of the sampled lines must match.
    if sample_lines:
        apache_hits = sum(1 for ln in sample_lines if _APACHE_RE.match(ln))
        if apache_hits >= max(1, len(sample_lines) // 2):
            return "apache"
        syslog_hits = sum(1 for ln in sample_lines if _SYSLOG_RE.match(ln))
        if syslog_hits >= max(1, len(sample_lines) // 2):
            return "syslog"

    # Delimited? Require a consistent delimiter across the first few lines.
    delim = _sniff_delimiter(text)
    if delim is not None:
        return "csv"

    # logfmt: lines dominated by key=value pairs.
    if _looks_like_logfmt("\n".join(sample_lines)):
        return "logfmt"

    # Anything else — the generic line parser will still turn it into events.
    return "generic"


def _sniff_delimiter(text: str) -> Optional[str]:
    """Return a delimiter if the first non-empty lines look consistently split."""
    lines = [ln for ln in text.splitlines() if ln.strip()][:10]
    if len(lines) < 2:
        return None
    for delim in (",", "\t", ";", "|"):
        counts = [ln.count(delim) for ln in lines]
        if counts[0] >= 1 and len(set(counts)) == 1:
            return delim
    return None


_LOGFMT_PAIR = re.compile(r'(\w[\w.\-]*)=("(?:[^"\\]|\\.)*"|\S+)')


def _looks_like_logfmt(sample: str) -> bool:
    lines = [ln for ln in sample.splitlines() if ln.strip()]
    if not lines:
        return False
    hits = sum(1 for ln in lines if len(_LOGFMT_PAIR.findall(ln)) >= 2)
    return hits >= max(1, len(lines) // 2)


# -----------------------------------------------------------------------------
# CSV / TSV / delimited
# -----------------------------------------------------------------------------
# Map common alternate column names → our normalised names.
_CSV_COLUMN_ALIASES: Dict[str, str] = {
    "time": "timestamp",
    "datetime": "timestamp",
    "date": "timestamp",
    "ts": "timestamp",
    "@timestamp": "timestamp",
    "event_time": "timestamp",
    "src_ip": "source_ip",
    "src": "source_ip",
    "srcip": "source_ip",
    "client_ip": "source_ip",
    "source": "source_ip",
    "ip": "source_ip",
    "remote_addr": "source_ip",
    "dst_ip": "dest_ip",
    "dst": "dest_ip",
    "dstip": "dest_ip",
    "destination_ip": "dest_ip",
    "dst_host": "dest_ip",
    "dest_host": "dest_ip",
    "target": "dest_ip",
    "event": "event_type",
    "action": "event_type",
    "alert_type": "event_type",
    "eventtype": "event_type",
    "type": "event_type",
    "category": "event_type",
    "username": "user",
    "account": "user",
    "src_user": "user",
    "user_name": "user",
    "account_name": "user",
    "result": "status",
    "outcome": "status",
    "response": "status",
    "status_code": "status",
    "size": "bytes",
    "length": "bytes",
    "bytes_out": "bytes",
    "bytes_sent": "bytes",
    "content_length": "bytes",
    "dest_port": "port",
    "dst_port": "port",
    "destination_port": "port",
}

# Fields that mean the same as `source_ip` etc. but should not clobber a real
# value — only the first alias to land wins (handled in _apply_aliases).
_PRIMARY_FOR = {
    "timestamp": ("timestamp", "@timestamp", "ts", "datetime", "date", "time", "event_time"),
    "source_ip": ("src_ip", "source_ip", "srcip", "src", "client_ip", "remote_addr", "ip", "source"),
    "dest_ip": ("dst_ip", "dest_ip", "dstip", "dst", "destination_ip", "dst_host", "dest_host", "target"),
    "event_type": ("event_type", "eventtype", "alert_type", "event", "action", "type", "category"),
    "user": ("user", "username", "user_name", "src_user", "account", "account_name"),
    "status": ("status", "result", "outcome", "response", "status_code"),
    "bytes": ("bytes", "size", "length", "bytes_out", "bytes_sent", "content_length"),
    "port": ("port", "dest_port", "dst_port", "destination_port"),
}


def _apply_aliases(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rename source columns onto the normalised schema without losing data.

    Columns are already lower-cased by the caller. For each normalised target
    we pick the first present alias (in priority order) and rename it; any
    other aliases are kept under their original name so nothing is dropped.
    """
    cols = set(df.columns)
    rename: Dict[str, str] = {}
    for target, candidates in _PRIMARY_FOR.items():
        if target in cols:
            continue  # the file already has the canonical name
        for cand in candidates:
            if cand in cols and cand not in rename:
                rename[cand] = target
                break
    return df.rename(columns=rename) if rename else df


def _derive_status(df: pd.DataFrame) -> pd.DataFrame:
    """
    When a log encodes success/failure inside event_type or the message rather
    than a dedicated status field, derive it so the detection rules can fire.
    """
    if "status" in df.columns and df["status"].notna().any():
        return df
    haystack = pd.Series("", index=df.index, dtype=str)
    for col in ("event_type", "message", "raw"):
        if col in df.columns:
            haystack = haystack.str.cat(df[col].astype(str).str.lower(), sep=" ")
    if haystack.str.strip().eq("").all():
        return df
    derived = pd.Series(None, index=df.index, dtype=object)
    derived[haystack.str.contains(
        r"fail|denied|invalid|reject|blocked|unauthor|bad password|error",
        na=False, regex=True)] = "FAILED"
    derived[haystack.str.contains(
        r"success|accepted|allowed|granted|logon type|login_ok",
        na=False, regex=True)] = "SUCCESS"
    if "status" in df.columns:
        df["status"] = df["status"].where(df["status"].notna(), derived)
    else:
        df["status"] = derived
    return df


def _parse_csv(text: str) -> Tuple[pd.DataFrame, int]:
    """Delimited file with a header row. Delimiter is auto-sniffed."""
    delim = _sniff_delimiter(text) or ","
    try:
        df = pd.read_csv(
            io.StringIO(text), dtype=str, keep_default_na=False,
            sep=delim, engine="python", on_bad_lines="skip",
        )
    except Exception:
        # Last-resort: let pandas sniff the delimiter itself.
        df = pd.read_csv(
            io.StringIO(text), dtype=str, keep_default_na=False,
            sep=None, engine="python", on_bad_lines="skip",
        )
    if df.empty:
        return df, 0
    df.columns = [str(c).strip().lower() for c in df.columns]
    df = _apply_aliases(df)
    df["raw"] = df.astype(str).agg(" | ".join, axis=1)
    df = _derive_status(df)
    return df, 0


# -----------------------------------------------------------------------------
# JSON / JSONL / NDJSON
# -----------------------------------------------------------------------------
def _parse_json(text: str) -> Tuple[pd.DataFrame, int]:
    """Accept a JSON array, a single object, a wrapper object, or NDJSON."""
    text = text.strip()
    rows: List[Dict[str, Any]] = []
    dropped = 0

    parsed_whole = False
    try:
        doc = json.loads(text)
        parsed_whole = True
    except json.JSONDecodeError:
        doc = None

    if parsed_whole:
        if isinstance(doc, list):
            rows = [r for r in doc if isinstance(r, dict)]
            dropped = len(doc) - len(rows)
        elif isinstance(doc, dict):
            # Wrapper like {"events": [...]} / {"results": [...]} → unwrap it.
            list_vals = [v for v in doc.values()
                         if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)]
            rows = list_vals[0] if len(list_vals) == 1 else [doc]
        else:
            rows = []
    else:
        # Newline-delimited JSON (one object per line).
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                dropped += 1
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                dropped += 1

    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(), dropped

    df.columns = [str(c).strip().lower() for c in df.columns]
    df = _apply_aliases(df)
    df["raw"] = df.apply(lambda r: json.dumps(r.dropna().to_dict(), default=str), axis=1)
    df = _derive_status(df)
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
        rows.append(
            {
                "timestamp": _try_parse_apache_ts(m.group("ts")),
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
        msg = m.group("msg")
        ip_match = _IP_RE.search(msg)
        lower = msg.lower()
        status: Optional[str] = None
        if "failed" in lower or "invalid" in lower:
            status = "FAILED"
        elif "accepted" in lower or "success" in lower:
            status = "SUCCESS"
        user_match = re.search(r"\b(?:for|user)\s+(\S+)", msg)
        rows.append(
            {
                "timestamp": _try_parse_syslog_ts(m.group("ts"), current_year),
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
    delim = _sniff_delimiter(text) or ","
    df = pd.read_csv(
        io.StringIO(text), dtype=str, keep_default_na=False,
        sep=delim, engine="python", on_bad_lines="skip",
    )
    df.columns = [c.strip() for c in df.columns]
    rename = {
        "TimeCreated": "timestamp",
        "EventID": "event_type",
        "Computer": "dest_ip",
        "User": "user",
        "Message": "raw",
    }
    df = df.rename(columns={k: v for k, v in rename.items() if k in df.columns})
    if "event_type" in df.columns:
        df["status"] = df["event_type"].map(
            lambda e: "FAILED" if str(e) in {"4625", "529", "530"} else "SUCCESS"
        )
    df["source_ip"] = None
    df["bytes"] = None
    df["port"] = None
    if "raw" not in df.columns:
        df["raw"] = df.astype(str).agg(" | ".join, axis=1)
    return df, 0


# -----------------------------------------------------------------------------
# logfmt / key=value
#   ts=2026-05-20T08:12:03Z level=warn src=1.2.3.4 user=admin msg="bad login"
# -----------------------------------------------------------------------------
def _parse_logfmt(text: str) -> Tuple[pd.DataFrame, int]:
    rows: List[Dict[str, Any]] = []
    dropped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        pairs = _LOGFMT_PAIR.findall(line)
        if not pairs:
            dropped += 1
            continue
        rec: Dict[str, Any] = {}
        for k, v in pairs:
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1].replace('\\"', '"')
            rec[k.lower()] = v
        rec["raw"] = line
        rows.append(rec)
    df = pd.DataFrame(rows)
    if df.empty:
        return df, dropped
    df = _apply_aliases(df)
    df = _derive_status(df)
    return df, dropped


# -----------------------------------------------------------------------------
# Generic line parser — the universal fallback.
# Treats EVERY non-empty line as one event and extracts whatever it can.
# -----------------------------------------------------------------------------
_ISO_TS_RE = re.compile(
    r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
_US_TS_RE = re.compile(r'\b(\d{1,2}/\d{1,2}/\d{2,4}[ T]\d{2}:\d{2}:\d{2})')
_APACHE_TS_RE = re.compile(r'\[(\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]')
_SYSLOG_TS_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b')
_EPOCH_TS_RE = re.compile(r'\b(1\d{9})(?:\.\d+)?\b')
_USER_RE = re.compile(
    r'\b(?:user|username|account|src_user|for user|for)[=:\s]+["\']?([\w.\-\\@]+)',
    re.IGNORECASE,
)
_PORT_RE = re.compile(r'\b(?:port|dport|dst_port)[=:\s]+(\d{1,5})\b', re.IGNORECASE)


def _generic_extract_ts(line: str, year: int) -> Optional[datetime]:
    """Pull the most reliable timestamp out of a free-form log line."""
    m = _ISO_TS_RE.search(line)
    if m:
        try:
            return pd.to_datetime(m.group(1), utc=True).to_pydatetime()
        except Exception:  # noqa: BLE001
            pass
    m = _APACHE_TS_RE.search(line)
    if m:
        ts = _try_parse_apache_ts(m.group(1))
        if ts:
            return ts
    m = _US_TS_RE.search(line)
    if m:
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S",
                    "%m/%d/%YT%H:%M:%S", "%m/%d/%yT%H:%M:%S"):
            try:
                return datetime.strptime(m.group(1), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    m = _SYSLOG_TS_RE.search(line)
    if m:
        ts = _try_parse_syslog_ts(m.group(1), year)
        if ts:
            return ts
    m = _EPOCH_TS_RE.search(line)
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
        except (ValueError, OSError):
            pass
    return None


def _parse_generic(text: str) -> Tuple[pd.DataFrame, int]:
    """
    Universal fallback. Every non-empty line becomes an event. We extract a
    timestamp, the first IP, a user and a status heuristically — enough for the
    raw-content detection rules and the timeline to still work.
    """
    rows: List[Dict[str, Any]] = []
    year = datetime.now(timezone.utc).year
    for line in text.splitlines():
        if not line.strip():
            continue
        lower = line.lower()
        status: Optional[str] = None
        if any(w in lower for w in ("fail", "denied", "invalid", "error", "reject", "blocked")):
            status = "FAILED"
        elif any(w in lower for w in ("success", "accepted", "allowed", "granted")):
            status = "SUCCESS"
        ip = _IP_RE.search(line)
        user = _USER_RE.search(line)
        port = _PORT_RE.search(line)
        rows.append(
            {
                "timestamp": _generic_extract_ts(line, year),
                "source_ip": ip.group(0) if ip else None,
                "dest_ip": None,
                "event_type": "log_line",
                "user": user.group(1) if user else None,
                "status": status,
                "bytes": None,
                "port": int(port.group(1)) if port else None,
                "raw": line,
            }
        )
    return pd.DataFrame(rows), 0


# -----------------------------------------------------------------------------
# Dispatch table
# -----------------------------------------------------------------------------
_PARSERS = {
    "csv": _parse_csv,
    "json": _parse_json,
    "apache": _parse_apache,
    "syslog": _parse_syslog,
    "winevent": _parse_winevent_csv,
    "logfmt": _parse_logfmt,
    "generic": _parse_generic,
}


# -----------------------------------------------------------------------------
# Finalisation — coerce types, fill missing columns, drop bad timestamps
# -----------------------------------------------------------------------------
def _finalise(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure every normalised column exists and has the right dtype."""
    if df is None or df.empty:
        return pd.DataFrame(columns=NORMALISED_COLUMNS)

    # Add any missing columns as None.
    for col in NORMALISED_COLUMNS:
        if col not in df.columns:
            df[col] = None

    # Parse timestamps (already-parsed datetimes pass through unchanged).
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    except Exception:  # noqa: BLE001 — never let a weird column kill ingest
        df["timestamp"] = pd.NaT

    # Cast numerics safely (empty strings → NaN → nullable Int64).
    for num_col in ("bytes", "port"):
        try:
            df[num_col] = pd.to_numeric(df[num_col], errors="coerce").astype("Int64")
        except Exception:  # noqa: BLE001
            df[num_col] = pd.Series([pd.NA] * len(df), dtype="Int64")

    # Empty strings → None for string columns (cleaner downstream).
    for str_col in ("source_ip", "dest_ip", "event_type", "user", "status"):
        df[str_col] = df[str_col].replace({"": None, "nan": None, "None": None})

    # `raw` must always be a string.
    df["raw"] = df["raw"].astype(str)

    # Keep the normalised columns first, then anything extra the source gave us.
    extra_cols = [c for c in df.columns if c not in NORMALISED_COLUMNS]
    return df[NORMALISED_COLUMNS + extra_cols]
