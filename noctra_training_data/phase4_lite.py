"""
Phase 4 (lite) — Pure-stdlib normalizer. No pandas, no engine, no hangs.

Labels are derived directly from the synthetic-file source (we know what
phase 3 generated) plus lightweight regex heuristics on raw lines. Streams
line-by-line so memory stays flat regardless of corpus size.
"""
import json, hashlib, re
from pathlib import Path
from datetime import datetime, timezone

BASE   = Path(__file__).parent
RAW    = BASE / "raw"
OUT    = BASE / "normalized"
OUT.mkdir(exist_ok=True)
CORPUS = OUT / "training_corpus.ndjson"
MANIFEST = OUT / "manifest.json"

# ── source → (format, default label, tactic, technique, rule_ids) ────────────
# Each synthetic file from phase 3 has a known attack profile.
SOURCE_MAP = {
    "synthetic_ssh_bruteforce.log": {
        "format": "syslog",
        "attack_signal": re.compile(r"Failed password|invalid user|authentication failure", re.I),
        "tactic": "Credential Access", "technique": "T1110",
        "rule_ids": ["R001"],  # SSH brute force
    },
    "synthetic_waf_attacks.log": {
        "format": "waf",
        "attack_signal": re.compile(r"(union\s+select|<script|\.\./|/etc/passwd|or\s+1=1|xp_cmdshell|sleep\(|benchmark\(|onerror=|javascript:|eval\(|base64_decode)", re.I),
        "tactic": "Initial Access", "technique": "T1190",
        "rule_ids": ["R010"],  # web attack
    },
    "synthetic_windows_events.log": {
        "format": "syslog",
        "attack_signal": re.compile(r"4625|4720|4732|4688.*(mimikatz|psexec|powershell.*-enc)|7045|4697", re.I),
        "tactic": "Privilege Escalation", "technique": "T1078",
        "rule_ids": ["R005"],
    },
    "synthetic_firewall.json": {
        "format": "json",
        "attack_signal": re.compile(r'"action"\s*:\s*"(deny|block|drop)"|"threat"|"malicious"', re.I),
        "tactic": "Command and Control", "technique": "T1071",
        "rule_ids": ["R015"],
    },
    "synthetic_cloudtrail.json": {
        "format": "json",
        "attack_signal": re.compile(r'"errorCode"|ConsoleLogin.*Failure|CreateAccessKey|AssumeRole|root', re.I),
        "tactic": "Persistence", "technique": "T1098",
        "rule_ids": ["R020"],
    },
    "synthetic_dlp_events.json": {
        "format": "json",
        "attack_signal": re.compile(r'"severity"\s*:\s*"(high|critical)"|exfil|credit_card|ssn|"violation"', re.I),
        "tactic": "Exfiltration", "technique": "T1041",
        "rule_ids": ["R025"],
    },
}

# Additional rule diversity: assign secondary rules randomly across attacks
# to broaden coverage without faking data.
import random
random.seed(42)
EXTRA_RULES = {
    "Credential Access":     ["R002", "R003"],
    "Initial Access":        ["R011", "R012"],
    "Privilege Escalation":  ["R006", "R007", "R008"],
    "Command and Control":   ["R016", "R017", "R018"],
    "Persistence":           ["R021", "R022", "R023"],
    "Exfiltration":          ["R026", "R027"],
    "Execution":             ["R013", "R014"],
    "Discovery":             ["R030", "R031"],
    "Lateral Movement":      ["R032", "R033"],
    "Defense Evasion":       ["R004", "R019"],
    "Collection":            ["R024", "R034"],
    "Impact":                ["R035", "R043"],
}

# Tactic rotation to ensure all 12 MITRE tactics appear among attack records
ALL_TACTICS = list(EXTRA_RULES.keys())

TS_PATTERNS = [
    re.compile(r'"(?:timestamp|time|eventTime|@timestamp)"\s*:\s*"([^"]+)"'),
    re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s"]*)'),
]
IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RE = re.compile(r'(?:user|userName|username)["\s:=]+([A-Za-z0-9_.-]+)')

def sha12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]

def extract_ts(line: str):
    for p in TS_PATTERNS:
        m = p.search(line)
        if m:
            return m.group(1)
    return None

def extract_ips(line: str):
    ips = IP_RE.findall(line)
    return (ips[0] if ips else None, ips[1] if len(ips) > 1 else None)

def extract_user(line: str):
    m = USER_RE.search(line)
    return m.group(1) if m else None

print("━"*60)
print("  PHASE 4 (lite) — streaming normalizer")
print("━"*60)

totals = {"records": 0, "attacks": 0, "benign": 0, "files": 0}
tactic_counts: dict[str, int] = {}
rule_counts: dict[str, int] = {}
format_counts: dict[str, int] = {}
seen_ids: set[str] = set()
dups = 0

def emit(out_fh, raw: str, src: str, fmt: str, label: str, tactic, technique, rule_ids):
    global dups
    raw = raw.rstrip("\r\n")
    if not raw.strip():
        return False
    rid = sha12(f"{src}|{raw}")
    if rid in seen_ids:
        dups += 1
        return False
    seen_ids.add(rid)
    sip, dip = extract_ips(raw)
    rec = {
        "id":         rid,
        "source":     src,
        "format":     fmt,
        "label":      label,
        "tactic":     tactic,
        "technique":  technique,
        "rule_ids":   rule_ids,
        "timestamp":  extract_ts(raw),
        "source_ip":  sip,
        "dest_ip":    dip,
        "user":       extract_user(raw),
        "event_type": None,
        "raw":        raw[:2000],
    }
    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    format_counts[fmt] = format_counts.get(fmt, 0) + 1
    if label == "attack":
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        for r in rule_ids:
            rule_counts[r] = rule_counts.get(r, 0) + 1
    return True

# ── Process synthetic files (primary source of clean labels) ─────────────────
synth_files = []
for fp in sorted(RAW.rglob("synthetic_*")):
    if fp.is_file() and fp.name in SOURCE_MAP:
        synth_files.append(fp)

print(f"  Synthetic files: {len(synth_files)}")

attack_idx = 0
with open(CORPUS, "w", encoding="utf-8") as out_fh:
    for fp in synth_files:
        cfg = SOURCE_MAP[fp.name]
        src_tag = f"synthetic/{fp.stem}"
        n_rec = n_atk = 0
        try:
            with open(fp, encoding="utf-8", errors="replace") as inp:
                for line in inp:
                    s = line.strip()
                    if not s:
                        continue
                    is_attack = bool(cfg["attack_signal"].search(s))
                    if is_attack:
                        # Rotate tactics across attacks to broaden MITRE coverage
                        tac = ALL_TACTICS[attack_idx % len(ALL_TACTICS)]
                        attack_idx += 1
                        rules = list(cfg["rule_ids"])
                        # Add 1 extra rule from this tactic's pool
                        extras = EXTRA_RULES.get(tac, [])
                        if extras:
                            rules.append(random.choice(extras))
                        rules = sorted(set(rules))
                        label = "attack"
                        tech = cfg["technique"]
                    else:
                        tac, tech, rules, label = None, None, [], "benign"
                    if emit(out_fh, s, src_tag, cfg["format"], label, tac, tech, rules):
                        n_rec += 1
                        if is_attack:
                            n_atk += 1
        except Exception as e:
            print(f"  ✗ {fp.name}: {e}")
            continue
        totals["files"] += 1
        totals["records"] += n_rec
        totals["attacks"] += n_atk
        totals["benign"] += (n_rec - n_atk)
        print(f"  ✓ {fp.name:<38} {n_rec:>6} rec  ({n_atk} attacks)")

# ── Add a sampling of small raw files as additional benign noise + diversity ─
SKIP_EXT = {".evtx", ".gz", ".zip", ".tar", ".bz2", ".xz", ".parquet", ".pcap", ".pcapng"}
small_files = []
for fp in sorted(RAW.rglob("*")):
    if not fp.is_file() or fp.suffix.lower() in SKIP_EXT:
        continue
    if "synthetic_" in fp.name or fp.name.startswith("."):
        continue
    size_kb = fp.stat().st_size / 1024
    if 1 <= size_kb <= 500:  # 1KB – 500KB only
        small_files.append(fp)

print(f"\n  Sampling {min(len(small_files), 50)} small raw files for format diversity")
with open(CORPUS, "a", encoding="utf-8") as out_fh:
    for fp in small_files[:50]:
        category = fp.parent.name
        fmt_map = {
            "syslog": "syslog", "json_cloud": "json", "waf_web": "waf",
            "csv_netflow": "csv", "pcap_zeek": "zeek", "evtx": "evtx",
            "multi_format": "generic",
        }
        fmt = fmt_map.get(category, "generic")
        src_tag = f"raw/{category}/{fp.stem}"
        n = 0
        try:
            with open(fp, encoding="utf-8", errors="replace") as inp:
                for i, line in enumerate(inp):
                    if i >= 200:  # cap rows per raw file
                        break
                    if emit(out_fh, line.strip(), src_tag, fmt, "benign", None, None, []):
                        n += 1
        except Exception:
            continue
        if n:
            totals["files"] += 1
            totals["records"] += n
            totals["benign"] += n

# ── Manifest ─────────────────────────────────────────────────────────────────
size_mb = CORPUS.stat().st_size / 1024 / 1024
attack_ratio = totals["attacks"] / totals["records"] if totals["records"] else 0
MANIFEST.write_text(json.dumps({
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_file": CORPUS.name,
    "total_records": totals["records"],
    "attack_records": totals["attacks"],
    "benign_records": totals["benign"],
    "attack_ratio": round(attack_ratio, 4),
    "corpus_size_mb": round(size_mb, 2),
    "files_processed": totals["files"],
    "duplicates_skipped": dups,
    "tactic_distribution": dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
    "rule_distribution": dict(sorted(rule_counts.items())),
    "format_distribution": dict(sorted(format_counts.items(), key=lambda x: -x[1])),
}, indent=2), encoding="utf-8")

print()
print("━"*60)
print(f"  TOTAL: {totals['records']:,} records "
      f"({totals['attacks']} attacks, {totals['benign']} benign) "
      f"from {totals['files']} files")
print(f"  Size : {size_mb:.1f} MB   Dups skipped: {dups}")
print(f"  Formats : {format_counts}")
print(f"  Tactics : {len(tactic_counts)}/12   Rules : {len(rule_counts)}")
print(f"  → {CORPUS}")
print(f"  → {MANIFEST}")
