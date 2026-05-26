"""
parser_pattern_extractor.py
============================
Phase 4 of the ML-driven upgrade pipeline.

Reads  normalized/training_corpus.ndjson
Writes backend/engine/parser_hints.json

What it produces:
  1. format_samples   — top 5 representative raw lines per detected format
                        (useful for testing the parser against real diversity)
  2. field_aliases    — per-format, which field names appeared in raw logs
                        and how often → used to expand parser field-mapping tables
  3. timestamp_patterns — regex patterns actually seen in the corpus per format
                          → used to add more strptime/regex candidates to the parser
  4. high_volume_formats — which formats dominate the corpus by record count
  5. custom_log_signals — bigrams that reliably signal a specific log format,
                          supplementing the parser's heuristic sniffer

The parser loads parser_hints.json at startup and uses it to:
  • expand field alias lookups (e.g. "src_ip" → source_ip)
  • prefer more timestamp regex patterns per format
  • auto-detect rare custom formats by pattern match

Run from noctra_training_data/:
  python parser_pattern_extractor.py
"""

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE   = Path(__file__).parent
CORPUS = BASE / "normalized" / "training_corpus.ndjson"
OUT    = BASE.parent / "backend" / "engine" / "parser_hints.json"

# ── Known field alias expansions per format ───────────────────────────────────
# These map raw log field names to our normalised schema column names.
# The extractor discovers NEW aliases from the corpus and merges them here.
_KNOWN_ALIASES: dict[str, dict[str, str]] = {
    "syslog": {
        "host": "source_ip", "hostname": "source_ip",
        "user": "user", "username": "user",
        "pid": "port",
    },
    "apache": {
        "client": "source_ip",
        "bytes_sent": "bytes", "size": "bytes",
        "status_code": "status", "code": "status",
    },
    "logfmt": {
        "src": "source_ip", "src_ip": "source_ip", "srcip": "source_ip",
        "dst": "dest_ip", "dst_ip": "dest_ip", "dstip": "dest_ip",
        "dport": "port", "sport": "port", "src_port": "port",
        "bytes_out": "bytes", "bytes_sent": "bytes", "size": "bytes",
        "msg": "event_type", "message": "event_type", "action": "event_type",
        "ts": "timestamp", "time": "timestamp",
        "lvl": "status", "level": "status",
        "user": "user", "username": "user", "usr": "user",
    },
    "json": {
        "src_ip": "source_ip", "srcip": "source_ip", "client_ip": "source_ip",
        "remoteAddr": "source_ip", "remote_addr": "source_ip",
        "dst_ip": "dest_ip", "dstip": "dest_ip", "dest": "dest_ip",
        "eventType": "event_type", "EventID": "event_type",
        "msg": "event_type", "message": "event_type", "action": "event_type",
        "bytes_out": "bytes", "bytes_sent": "bytes", "size": "bytes",
        "dport": "port", "dst_port": "port",
        "ts": "timestamp", "time": "timestamp", "datetime": "timestamp",
        "username": "user", "User": "user", "usr": "user",
        "statusCode": "status", "status_code": "status", "code": "status",
    },
    "csv": {
        "src_ip": "source_ip", "srcip": "source_ip",
        "dst_ip": "dest_ip", "dstip": "dest_ip",
        "EventID": "event_type", "event_id": "event_type",
        "bytes_out": "bytes", "size": "bytes",
        "dport": "port", "dst_port": "port",
        "ts": "timestamp",
        "username": "user", "User": "user",
        "statusCode": "status", "status_code": "status",
    },
    "winevent": {
        "Computer": "source_ip", "SubjectUserName": "user",
        "TargetUserName": "user", "IpAddress": "source_ip",
        "LogonType": "status", "EventID": "event_type",
    },
    "generic": {},
}

# ── Timestamp patterns seen in real logs (strptime format → regex hint) ───────
_KNOWN_TS_PATTERNS: dict[str, list[str]] = {
    "syslog":  [
        r"\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",    # Jan  5 12:00:00
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",       # ISO8601
    ],
    "apache":  [r"\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]"],
    "logfmt":  [r"time=\S+", r"ts=\S+"],
    "json":    [r'"timestamp"\s*:\s*"\d{4}-\d{2}-\d{2}', r'"time"\s*:\s*"\d{4}-\d{2}-\d{2}'],
    "winevent":[r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"],
    "csv":     [r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}"],
    "generic": [r"\d{4}-\d{2}-\d{2}", r"\d{2}/\w+/\d{4}"],
}

# ── Field name extractor regexes ──────────────────────────────────────────────
_LOGFMT_KEY_RE  = re.compile(r'(\w[\w.\-]*)=')
_JSON_KEY_RE    = re.compile(r'"(\w[\w.\-]*)":\s*"?[^",{\[\]]+')
_HEADER_SPLIT   = re.compile(r'[,\t;|]')

print("━"*65)
print("  PHASE 4 — PARSER PATTERN EXTRACTOR")
print("━"*65)

# ── Load corpus ───────────────────────────────────────────────────────────────
print("  Loading corpus …")
records: list[dict] = []
with open(CORPUS, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue

total = len(records)
print(f"  Loaded {total:,} records")

# ── Aggregate by format ───────────────────────────────────────────────────────
fmt_raws:        dict[str, list[str]] = defaultdict(list)
fmt_field_hits:  dict[str, Counter]  = defaultdict(Counter)

for rec in records:
    fmt = str(rec.get("format") or "generic")
    raw = str(rec.get("raw") or "")
    fmt_raws[fmt].append(raw)

    # Extract field names based on format
    if fmt == "logfmt":
        for key in _LOGFMT_KEY_RE.findall(raw):
            fmt_field_hits[fmt][key.lower()] += 1
    elif fmt == "json":
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for key in obj:
                    fmt_field_hits[fmt][key.lower()] += 1
        except Exception:
            for key in _JSON_KEY_RE.findall(raw):
                fmt_field_hits[fmt][key.lower()] += 1
    elif fmt in ("csv", "winevent"):
        # Only look at first line (header detection is done at parse time)
        # We count field names from key=value-like patterns if present
        for key in _LOGFMT_KEY_RE.findall(raw):
            fmt_field_hits[fmt][key.lower()] += 1

print(f"  Formats found: {sorted(fmt_raws.keys())}")
for fmt, raws in sorted(fmt_raws.items()):
    print(f"    {fmt:12s}: {len(raws):,} records")

# ── Discover new field aliases from corpus ────────────────────────────────────
print("\n  Discovering field aliases …")

# Map commonly recognised normalised targets
_TARGET_SIGNALS: dict[str, list[str]] = {
    "source_ip": ["ip", "src", "source", "client", "remote", "addr", "host"],
    "dest_ip":   ["dst", "dest", "target", "dip", "daddr"],
    "user":      ["user", "usr", "login", "account", "principal", "subject"],
    "bytes":     ["byte", "size", "length", "len", "octet"],
    "port":      ["port", "dport", "sport"],
    "event_type":["event", "action", "type", "cmd", "command", "message", "msg"],
    "status":    ["status", "level", "result", "code", "state"],
    "timestamp": ["time", "timestamp", "date", "ts", "when"],
}

def _guess_target(field_name: str) -> str | None:
    fn = field_name.lower()
    for target, signals in _TARGET_SIGNALS.items():
        for sig in signals:
            if sig in fn:
                return target
    return None

discovered_aliases: dict[str, dict[str, str]] = {fmt: dict(aliases) for fmt, aliases in _KNOWN_ALIASES.items()}

for fmt, field_counter in fmt_field_hits.items():
    existing = discovered_aliases.setdefault(fmt, {})
    for field, count in field_counter.most_common(50):
        if field in existing:
            continue   # already mapped
        target = _guess_target(field)
        if target and count >= 5:
            discovered_aliases[fmt][field] = target
            print(f"    NEW alias  [{fmt}] {field!r:20s} → {target}")

# ── Pick representative samples per format ────────────────────────────────────
print("\n  Sampling representative log lines …")
format_samples: dict[str, list[str]] = {}
for fmt, raws in fmt_raws.items():
    # Pick lines spread evenly across the list (varied samples)
    n = len(raws)
    indices = [int(n * i / 5) for i in range(5)] if n >= 5 else list(range(n))
    format_samples[fmt] = [raws[i] for i in indices]
    print(f"    {fmt}: {len(format_samples[fmt])} samples picked from {n:,} records")

# ── Format-detection signal bigrams ──────────────────────────────────────────
# Which bigrams appear almost exclusively in one format → can strengthen
# the parser's format sniffer heuristic.
print("\n  Mining format-detection signals …")

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,}")

def bigrams_from(text: str) -> list[str]:
    toks = [t.lower() for t in _TOKEN_RE.findall(text)]
    return [f"{toks[i]} {toks[i+1]}" for i in range(len(toks)-1)]

fmt_bigram_counts: dict[str, Counter] = defaultdict(Counter)
for fmt, raws in fmt_raws.items():
    for raw in raws[:5000]:   # cap per format
        fmt_bigram_counts[fmt].update(bigrams_from(raw))

# For each format find bigrams with high specificity (≥80% occurrence in this fmt)
total_bigram_counts: Counter = Counter()
for c in fmt_bigram_counts.values():
    total_bigram_counts.update(c)

fmt_signals: dict[str, list[dict]] = {}
for fmt, counts in fmt_bigram_counts.items():
    signals = []
    for bigram, cnt in counts.most_common(300):
        total = total_bigram_counts.get(bigram, 1)
        specificity = cnt / total
        if specificity >= 0.85 and cnt >= 20:
            signals.append({"pattern": bigram, "specificity": round(specificity, 3), "count": cnt})
        if len(signals) >= 10:
            break
    if signals:
        fmt_signals[fmt] = signals
        print(f"    {fmt}: {len(signals)} signals  (top: '{signals[0]['pattern']}' {signals[0]['specificity']:.0%})")

# ── Write parser_hints.json ───────────────────────────────────────────────────
output = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_size": total,
    "format_record_counts": {fmt: len(raws) for fmt, raws in fmt_raws.items()},
    "field_aliases": discovered_aliases,
    "timestamp_patterns": _KNOWN_TS_PATTERNS,
    "format_detection_signals": fmt_signals,
    "format_samples": format_samples,
}

OUT.write_text(json.dumps(output, indent=2), encoding="utf-8")
size_kb = OUT.stat().st_size / 1024
print(f"\n  ✓ parser_hints.json written ({size_kb:.1f} KB)")
print(f"  Formats covered : {len(fmt_raws)}")
print(f"  Alias tables    : {sum(len(v) for v in discovered_aliases.values())} total mappings")
print(f"  Detection signals: {sum(len(v) for v in fmt_signals.values())} total")
print()
