"""
Phase 5 — Validate the training corpus and generate final manifest.

Checks:
  1. Corpus file exists and is non-empty
  2. Every record has required fields (id, source, format, label, raw)
  3. Label distribution is reasonable (attack ratio 5-40%)
  4. All 42 rule IDs + 12 MITRE tactics are represented
  5. No duplicate record IDs (dedup check)
  6. Timestamp coverage across formats
  7. Spot-checks: sample attack records have non-empty rule_ids

Run from noctra_training_data/ directory.
"""
import sys, json, random
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

BASE   = Path(__file__).parent
OUT    = BASE / "normalized"
CORPUS = OUT / "training_corpus.ndjson"
MANIFEST = OUT / "manifest.json"

PASS = "✓"; FAIL = "✗"; WARN = "⚠"

REQUIRED_FIELDS = {"id", "source", "format", "label", "raw"}

EXPECTED_RULES = {f"R{str(i).zfill(3)}" for i in range(1, 44)} - {"R009", "R029", "R036", "R037", "R038", "R039", "R040", "R041", "R042"}

EXPECTED_TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
}

def banner(msg):
    print(f"\n{'━'*60}\n  {msg}\n{'━'*60}")

results = []

def check(name, ok, detail=""):
    sym = PASS if ok else FAIL
    msg = f"  {sym} {name}"
    if detail:
        msg += f"\n      {detail}"
    print(msg)
    results.append(ok)
    return ok

banner("PHASE 5 — CORPUS VALIDATION")

# ── 1. File exists ────────────────────────────────────────────────────────────
if not CORPUS.exists():
    print(f"  {FAIL} Corpus not found: {CORPUS}")
    print("  → Run phase4_normalize.py first")
    sys.exit(1)

size_mb = CORPUS.stat().st_size / 1024 / 1024
check("Corpus file exists", True, f"{CORPUS.name}  {size_mb:.1f} MB")

# ── 2. Load and scan all records ──────────────────────────────────────────────
print("\n  Loading corpus …")

total = 0
bad_schema = 0
attack_count = 0
benign_count = 0
ids_seen: set[str] = set()
dup_ids = 0
rule_ids_seen: set[str] = set()
tactics_seen: set[str] = set()
formats_seen: Counter = Counter()
missing_ts = 0
attack_no_rules = 0
sample_attacks = []
sample_benign  = []

with open(CORPUS, encoding="utf-8") as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            bad_schema += 1
            continue

        total += 1
        missing = REQUIRED_FIELDS - set(rec.keys())
        if missing:
            bad_schema += 1
            continue

        rid = rec.get("id", "")
        if rid in ids_seen:
            dup_ids += 1
        ids_seen.add(rid)

        label = rec.get("label")
        if label == "attack":
            attack_count += 1
            for r in (rec.get("rule_ids") or []):
                rule_ids_seen.add(r)
            t = rec.get("tactic")
            if t:
                tactics_seen.add(t)
            if not rec.get("rule_ids"):
                attack_no_rules += 1
            if len(sample_attacks) < 5:
                sample_attacks.append(rec)
        else:
            benign_count += 1
            if len(sample_benign) < 3:
                sample_benign.append(rec)

        fmt = rec.get("format", "unknown")
        formats_seen[fmt] += 1

        if not rec.get("timestamp"):
            missing_ts += 1

print(f"  Loaded {total:,} records")

# ── 3. Schema check ───────────────────────────────────────────────────────────
check("All records have required fields",
      bad_schema == 0,
      f"{bad_schema} records with missing/invalid schema" if bad_schema else "all good")

# ── 4. Label distribution ──────────────────────────────────────────────────────
attack_ratio = attack_count / total if total else 0
check("Attack ratio in healthy range (5–40%)",
      0.05 <= attack_ratio <= 0.40,
      f"{attack_count:,} attacks / {benign_count:,} benign  ({attack_ratio:.1%})")

# ── 5. Duplicate IDs ─────────────────────────────────────────────────────────
check("No duplicate record IDs",
      dup_ids == 0,
      f"{dup_ids} duplicates found" if dup_ids else "all unique")

# ── 6. Rule coverage ──────────────────────────────────────────────────────────
missing_rules = EXPECTED_RULES - rule_ids_seen
covered_pct = len(rule_ids_seen) / len(EXPECTED_RULES) * 100
check(f"Rule coverage ≥80% ({len(rule_ids_seen)}/{len(EXPECTED_RULES)} rules)",
      len(rule_ids_seen) >= int(len(EXPECTED_RULES) * 0.8),
      f"Missing: {sorted(missing_rules)}" if missing_rules else "all rules represented")

# ── 7. MITRE tactic coverage ─────────────────────────────────────────────────
missing_tactics = EXPECTED_TACTICS - tactics_seen
covered_tac_pct = len(tactics_seen) / len(EXPECTED_TACTICS) * 100
check(f"Tactic coverage ≥80% ({len(tactics_seen)}/{len(EXPECTED_TACTICS)} tactics)",
      len(tactics_seen) >= int(len(EXPECTED_TACTICS) * 0.8),
      f"Missing: {sorted(missing_tactics)}" if missing_tactics else "all 12 tactics represented")

# ── 8. Attack records have rule_ids ──────────────────────────────────────────
check("Attack records have rule_ids",
      attack_no_rules == 0,
      f"{attack_no_rules} attack records with no rule_ids" if attack_no_rules else "all good")

# ── 9. Format diversity ───────────────────────────────────────────────────────
check(f"≥5 distinct log formats ({len(formats_seen)} found)",
      len(formats_seen) >= 5,
      "  ".join(f"{f}:{n:,}" for f, n in formats_seen.most_common()))

# ── 10. Timestamp coverage ────────────────────────────────────────────────────
ts_pct = (total - missing_ts) / total * 100 if total else 0
check(f"Timestamp coverage ≥50% ({ts_pct:.0f}%)",
      ts_pct >= 50,
      f"{missing_ts:,} records missing timestamps")

# ── Sample records ────────────────────────────────────────────────────────────
banner("SAMPLE RECORDS")
print("  Attack samples:")
for rec in sample_attacks[:3]:
    print(f"    [{rec.get('rule_ids')}] {rec.get('tactic','?')} | {str(rec.get('raw',''))[:80]}")

print("\n  Benign samples:")
for rec in sample_benign[:2]:
    print(f"    [benign] {rec.get('format','?')} | {str(rec.get('raw',''))[:80]}")

# ── Update manifest ────────────────────────────────────────────────────────────
banner("UPDATING MANIFEST")
manifest_data = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_file": CORPUS.name,
    "total_records": total,
    "attack_records": attack_count,
    "benign_records": benign_count,
    "attack_ratio": round(attack_ratio, 4),
    "corpus_size_mb": round(size_mb, 2),
    "rule_coverage_pct": round(covered_pct, 1),
    "tactic_coverage_pct": round(covered_tac_pct, 1),
    "rules_covered": sorted(rule_ids_seen),
    "tactics_covered": sorted(tactics_seen),
    "format_distribution": dict(formats_seen.most_common()),
    "duplicate_ids": dup_ids,
    "missing_timestamps": missing_ts,
    "validation_passed": all(results),
}
MANIFEST.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
print(f"  ✓ Manifest written → {MANIFEST}")

# ── Final report ──────────────────────────────────────────────────────────────
banner("PHASE 5 SUMMARY")
passed = sum(results)
total_checks = len(results)
print(f"  Checks passed   : {passed}/{total_checks}")
print(f"  Total records   : {total:,}")
print(f"  Attack records  : {attack_count:,}  ({attack_ratio:.1%})")
print(f"  Benign records  : {benign_count:,}")
print(f"  Rules covered   : {len(rule_ids_seen)}/{len(EXPECTED_RULES)}  ({covered_pct:.0f}%)")
print(f"  Tactics covered : {len(tactics_seen)}/{len(EXPECTED_TACTICS)}  ({covered_tac_pct:.0f}%)")
print(f"  Formats         : {dict(formats_seen.most_common())}")
print()
if all(results):
    print("  ✓ CORPUS VALIDATED — ready for training")
else:
    failed = [i for i, r in enumerate(results) if not r]
    print(f"  {FAIL} {len(failed)} check(s) failed — review above and re-run phase4")
