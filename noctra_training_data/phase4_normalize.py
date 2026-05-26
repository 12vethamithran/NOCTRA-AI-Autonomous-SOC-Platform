"""
Phase 4 — Normalize all raw + synthetic logs into unified NDJSON training records.

Output schema (one JSON object per line):
  {
    "id":          "<sha256 hex of raw>[:12]",
    "source":      "<dataset name>",
    "format":      "<detected format>",
    "label":       "attack" | "benign",
    "tactic":      "<MITRE tactic or null>",
    "technique":   "<T1xxx or null>",
    "rule_ids":    ["R001", ...],
    "timestamp":   "<ISO8601 or null>",
    "source_ip":   "<ip or null>",
    "dest_ip":     "<ip or null>",
    "user":        "<user or null>",
    "event_type":  "<str or null>",
    "raw":         "<original log line>"
  }

Run from noctra_training_data/ directory.
"""
import sys, os, json, hashlib
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pandas as pd
from engine.parser import parse
from engine.rules import run_all_rules, _RULE_REASONING

BASE    = Path(__file__).parent
RAW     = BASE / "raw"
SYNTH   = BASE / "synthetic"
OUT_DIR = BASE / "normalized"
ERRORS  = BASE / "errors.log"

OUT_DIR.mkdir(exist_ok=True)

def log_err(source: str, msg: str):
    with open(ERRORS, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] PHASE4 | {source} | {msg}\n")
    print(f"  ✗ {source}: {msg}")

def banner(msg: str):
    print(f"\n{'━'*60}\n  {msg}\n{'━'*60}")

def sha12(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]

def ts_to_iso(ts) -> str | None:
    if pd.isna(ts):
        return None
    try:
        return pd.Timestamp(ts).isoformat()
    except Exception:
        return None

def safe_str(v) -> str | None:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    return s if s and s != "nan" else None

# ─────────────────────────────────────────────────────────────────────────────
# Core: parse a file → normalize → append to output NDJSON
# ─────────────────────────────────────────────────────────────────────────────
def normalize_file(filepath: Path, source_tag: str, out_fh) -> dict:
    """Parse one file, run rules, write normalized records. Returns stats."""
    stats = {"records": 0, "attacks": 0, "benign": 0, "errors": 0}
    try:
        content = filepath.read_bytes()
        if not content.strip():
            return stats
        result = parse(filepath.name, content)
        df = result.dataframe
        if df.empty:
            return stats
    except Exception as e:
        log_err(str(filepath), f"parse error: {e}")
        stats["errors"] += 1
        return stats

    # Run detection rules to get alerts per row
    try:
        alerts = run_all_rules(df)
    except Exception as e:
        log_err(str(filepath), f"rules error: {e}")
        alerts = []

    # Build index: row_index → list of alerts
    row_alert_map: dict[int, list] = {}
    for alert in alerts:
        for idx in (alert.related_log_indices or []):
            row_alert_map.setdefault(idx, []).append(alert)

    for idx, row in df.iterrows():
        raw_val = safe_str(row.get("raw")) or ""
        if not raw_val:
            continue

        row_alerts = row_alert_map.get(idx, [])
        if row_alerts:
            label    = "attack"
            rule_ids = list({a.rule_id for a in row_alerts})
            tactic   = row_alerts[0].mitre_tactic
            technique = row_alerts[0].mitre_technique
        else:
            label     = "benign"
            rule_ids  = []
            tactic    = None
            technique = None

        rec = {
            "id":          sha12(raw_val),
            "source":      source_tag,
            "format":      result.detected_format,
            "label":       label,
            "tactic":      tactic,
            "technique":   technique,
            "rule_ids":    rule_ids,
            "timestamp":   ts_to_iso(row.get("timestamp")),
            "source_ip":   safe_str(row.get("source_ip")),
            "dest_ip":     safe_str(row.get("dest_ip")),
            "user":        safe_str(row.get("user")),
            "event_type":  safe_str(row.get("event_type")),
            "raw":         raw_val,
        }
        out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        stats["records"] += 1
        if label == "attack":
            stats["attacks"] += 1
        else:
            stats["benign"] += 1

    return stats

# ─────────────────────────────────────────────────────────────────────────────
# Walk raw datasets
# ─────────────────────────────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {
    ".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv",
    ".evtx",  # skip silently — binary format requires python-evtx
}
SKIP_EXTENSIONS = {".evtx", ".gz", ".zip", ".tar", ".bz2", ".xz", ".parquet"}

banner("PHASE 4 — NORMALIZING RAW DATASETS")

raw_out = OUT_DIR / "raw_normalized.ndjson"
total_raw = {"records": 0, "attacks": 0, "benign": 0, "errors": 0, "files": 0}

with open(raw_out, "w", encoding="utf-8") as fh:
    for subdir in sorted(RAW.iterdir()):
        if not subdir.is_dir():
            continue
        category = subdir.name
        files = sorted(f for f in subdir.rglob("*")
                       if f.is_file()
                       and f.suffix.lower() not in SKIP_EXTENSIONS
                       and f.name not in (".gitkeep", ".gitignore")
                       and f.stat().st_size > 0)
        if not files:
            print(f"  ↩  {category}: no files")
            continue
        cat_stats = {"records": 0, "attacks": 0, "benign": 0, "errors": 0, "files": 0}
        for fp in files:
            tag = f"raw/{category}/{fp.stem}"
            s = normalize_file(fp, tag, fh)
            for k in cat_stats:
                cat_stats[k] += s.get(k, 0)
            if s["records"] > 0:
                cat_stats["files"] += 1
        for k in total_raw:
            total_raw[k] += cat_stats[k]
        print(f"  ✓ {category:<22} {cat_stats['records']:>6} records  "
              f"({cat_stats['attacks']} attacks / {cat_stats['benign']} benign) "
              f"from {cat_stats['files']} files")

print(f"\n  RAW total: {total_raw['records']} records "
      f"({total_raw['attacks']} attacks / {total_raw['benign']} benign) "
      f"from {total_raw['files']} files")

# ─────────────────────────────────────────────────────────────────────────────
# Walk synthetic datasets
# ─────────────────────────────────────────────────────────────────────────────
banner("NORMALIZING SYNTHETIC DATASETS")

synth_out = OUT_DIR / "synthetic_normalized.ndjson"
total_synth = {"records": 0, "attacks": 0, "benign": 0, "errors": 0, "files": 0}

if not SYNTH.exists() or not any(SYNTH.iterdir()):
    print("  ↩  No synthetic data found — run phase3_synthetic.py first")
else:
    with open(synth_out, "w", encoding="utf-8") as fh:
        for fp in sorted(SYNTH.rglob("*")):
            if not fp.is_file():
                continue
            if fp.suffix.lower() in SKIP_EXTENSIONS or fp.stat().st_size == 0:
                continue
            tag = f"synthetic/{fp.stem}"
            s = normalize_file(fp, tag, fh)
            for k in total_synth:
                total_synth[k] += s.get(k, 0)
            if s["records"] > 0:
                total_synth["files"] += 1
                print(f"  ✓ {fp.name:<35} {s['records']:>6} records  "
                      f"({s['attacks']} attacks / {s['benign']} benign)")
    print(f"\n  SYNTH total: {total_synth['records']} records "
          f"({total_synth['attacks']} attacks / {total_synth['benign']} benign) "
          f"from {total_synth['files']} files")

# ─────────────────────────────────────────────────────────────────────────────
# Merge into a single training corpus
# ─────────────────────────────────────────────────────────────────────────────
banner("MERGING INTO UNIFIED CORPUS")

corpus_out = OUT_DIR / "training_corpus.ndjson"
manifest   = OUT_DIR / "manifest.json"

total_corpus = 0
attack_corpus = 0
benign_corpus = 0
tactic_counts: dict[str, int] = {}
rule_counts: dict[str, int] = {}

with open(corpus_out, "w", encoding="utf-8") as out:
    for src_file in (raw_out, synth_out):
        if not src_file.exists():
            continue
        with open(src_file, encoding="utf-8") as inp:
            for line in inp:
                line = line.strip()
                if not line:
                    continue
                out.write(line + "\n")
                total_corpus += 1
                try:
                    rec = json.loads(line)
                    if rec.get("label") == "attack":
                        attack_corpus += 1
                        t = rec.get("tactic")
                        if t:
                            tactic_counts[t] = tactic_counts.get(t, 0) + 1
                        for r in (rec.get("rule_ids") or []):
                            rule_counts[r] = rule_counts.get(r, 0) + 1
                    else:
                        benign_corpus += 1
                except Exception:
                    pass

size_mb = corpus_out.stat().st_size / 1024 / 1024 if corpus_out.exists() else 0

# Write manifest
manifest_data = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_file": str(corpus_out.name),
    "total_records": total_corpus,
    "attack_records": attack_corpus,
    "benign_records": benign_corpus,
    "attack_ratio": round(attack_corpus / total_corpus, 4) if total_corpus else 0,
    "corpus_size_mb": round(size_mb, 2),
    "tactic_distribution": dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
    "rule_distribution": dict(sorted(rule_counts.items())),
    "sources": {
        "raw": {k: total_raw[k] for k in ("records", "attacks", "benign", "files")},
        "synthetic": {k: total_synth[k] for k in ("records", "attacks", "benign", "files")},
    },
}
manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
banner("PHASE 4 SUMMARY")
print(f"  Corpus size     : {total_corpus:,} records ({size_mb:.1f} MB)")
print(f"  Attack records  : {attack_corpus:,}  ({100*attack_corpus/total_corpus:.1f}%)" if total_corpus else "  Attack records  : 0")
print(f"  Benign records  : {benign_corpus:,}  ({100*benign_corpus/total_corpus:.1f}%)" if total_corpus else "  Benign records  : 0")
print(f"\n  Tactic distribution:")
for tac, cnt in sorted(tactic_counts.items(), key=lambda x: -x[1])[:10]:
    print(f"    {tac:<35} {cnt:>6}")
print(f"\n  Rule hits:")
for rule, cnt in sorted(rule_counts.items())[:20]:
    print(f"    {rule:<8} {cnt:>6}")
print(f"\n  Output files:")
print(f"    {raw_out}")
print(f"    {synth_out}")
print(f"    {corpus_out}")
print(f"    {manifest}")
print(f"\n  ✓ Phase 4 complete — proceed to Phase 5 (validation)")
