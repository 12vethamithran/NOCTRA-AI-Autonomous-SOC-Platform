"""
corpus_analyser.py
==================
Phase 2 of the ML-driven upgrade pipeline.

Reads training_corpus.ndjson and produces rule_insights.json which the
rule_synthesiser (Phase 3) uses to tune thresholds and generate new rule
candidates.

What it does per rule:
  1. Collects all attack samples tagged with that rule_id
  2. Runs a fast F1-grid-search to find the optimal count/window threshold
  3. Extracts the top-N raw-line substrings from attack samples NOT covered
     by any existing rule → candidate patterns for new rules

Also produces:
  - uncovered_tactics: attack records that no rule_id covers → ML-only gaps
  - format_coverage:   which log formats have sparse rule coverage

Run from noctra_training_data/:
  python corpus_analyser.py
"""

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE   = Path(__file__).parent
CORPUS = BASE / "normalized" / "training_corpus.ndjson"
OUT    = BASE / "rule_insights.json"

# Backend rule config for reference
RULE_CONFIG = BASE.parent / "backend" / "engine" / "rule_config.json"

EXPECTED_RULES = {f"R{str(i).zfill(3)}" for i in range(1, 44)} - {
    "R009", "R029", "R036", "R037", "R038", "R039", "R040", "R041", "R042"
}

# ── Tokeniser for pattern mining ──────────────────────────────────────────────
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-\.]{2,}")  # meaningful words ≥3 chars
_SKIP_TOKENS = {
    "the", "and", "for", "with", "from", "that", "this", "are", "was",
    "has", "not", "but", "can", "its", "more", "also", "null", "none",
    "true", "false", "json", "http", "https", "com", "org", "net",
}

def tokenise(raw: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(raw) if t.lower() not in _SKIP_TOKENS]


def bigrams(tokens: list[str]) -> list[str]:
    return [f"{tokens[i]} {tokens[i+1]}" for i in range(len(tokens)-1)]


print("━"*65)
print("  PHASE 2 — CORPUS ANALYSER")
print("━"*65)

# ── Load corpus ───────────────────────────────────────────────────────────────
print("  Loading corpus …")
records = []
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
attacks = [r for r in records if r.get("label") == "attack"]
benign  = [r for r in records if r.get("label") == "benign"]
print(f"  Loaded {total:,} records ({len(attacks):,} attacks, {len(benign):,} benign)")

# ── Per-rule analysis ─────────────────────────────────────────────────────────
rule_samples:   dict[str, list[str]] = defaultdict(list)   # rule_id → raw lines
rule_tactics:   dict[str, Counter]   = defaultdict(Counter)
uncovered_raws: list[str] = []
tactic_counts:  Counter = Counter()
covered_count = 0

for rec in attacks:
    raw    = str(rec.get("raw") or "")
    rids   = rec.get("rule_ids") or []
    tactic = rec.get("tactic") or "Unknown"
    tactic_counts[tactic] += 1
    if rids:
        covered_count += 1
        for rid in rids:
            rule_samples[rid].append(raw)
            rule_tactics[rid][tactic] += 1
    else:
        uncovered_raws.append(raw)

print(f"  Rules coverage: {len(rule_samples)}/{len(EXPECTED_RULES)} rules have samples")
print(f"  Uncovered attack records (ML-only): {len(uncovered_raws):,}")

# ── Pattern mining per rule ───────────────────────────────────────────────────
# For each rule, find the most discriminative bigrams in attack samples
# vs benign baseline. Uses a simple lift metric: P(bigram|attack) / P(bigram|benign)

benign_token_counts: Counter = Counter()
for rec in benign[:20000]:  # cap for speed
    benign_token_counts.update(bigrams(tokenise(str(rec.get("raw") or ""))))
benign_total = max(sum(benign_token_counts.values()), 1)

def top_patterns(raws: list[str], top_n: int = 15) -> list[dict]:
    """Return top discriminative bigrams for a set of attack raw lines."""
    attack_counts: Counter = Counter()
    for r in raws:
        attack_counts.update(bigrams(tokenise(r)))
    attack_total = max(sum(attack_counts.values()), 1)
    scored = []
    for bigram, atk_cnt in attack_counts.most_common(200):
        ben_cnt = benign_token_counts.get(bigram, 0)
        atk_freq = atk_cnt / attack_total
        ben_freq = (ben_cnt + 1) / benign_total  # Laplace smoothing
        lift = atk_freq / ben_freq
        scored.append({"pattern": bigram, "attack_count": atk_cnt, "lift": round(lift, 2)})
    scored.sort(key=lambda x: -x["lift"])
    return scored[:top_n]


# ── F1-grid-search for count-threshold rules ─────────────────────────────────
# Rules R001/R002/R008/R020 fire based on a COUNT threshold.
# We simulate: for each candidate threshold, measure how well it separates
# the corpus (attack samples have many hits, benign have few).

def optimise_count_threshold(
    attack_raws: list[str],
    benign_raws: list[str],
    pattern: str,          # regex or substring to count hits
    current: int,
    candidates: list[int],
) -> dict:
    """Return the threshold that maximises F1 on the corpus."""
    pat = re.compile(pattern, re.I)

    def count_hits(raw: str) -> int:
        return len(pat.findall(raw))

    atk_counts = [count_hits(r) for r in attack_raws]
    ben_counts = [count_hits(r) for r in benign_raws[:len(attack_raws)*3]]  # balanced

    best = {"threshold": current, "f1": 0.0, "precision": 0.0, "recall": 0.0}
    for t in candidates:
        tp = sum(1 for c in atk_counts if c >= t)
        fn = sum(1 for c in atk_counts if c < t)
        fp = sum(1 for c in ben_counts if c >= t)
        prec = tp / max(tp + fp, 1)
        rec  = tp / max(tp + fn, 1)
        f1   = 2 * prec * rec / max(prec + rec, 1e-9)
        if f1 > best["f1"]:
            best = {"threshold": t, "f1": round(f1, 4),
                    "precision": round(prec, 4), "recall": round(rec, 4)}
    return best


benign_raws_sample = [str(r.get("raw") or "") for r in benign[:5000]]

# ── Build insights per rule ───────────────────────────────────────────────────
insights: dict[str, dict] = {}
for rid in sorted(EXPECTED_RULES):
    raws = rule_samples.get(rid, [])
    n = len(raws)
    patterns = top_patterns(raws) if raws else []

    entry: dict = {
        "rule_id": rid,
        "attack_samples": n,
        "top_tactics": dict(rule_tactics[rid].most_common(3)),
        "top_discriminative_patterns": patterns,
        "threshold_optimisation": None,
    }

    # Count-threshold rules: optimise them
    threshold_targets = {
        "R001": ("fail|failed password|authentication failure", "min_failures",  [2,3,4,5,6,8,10,12,15]),
        "R002": ("dport=|port=|\\.([0-9]{2,5})",               "min_distinct_ports", [5,8,10,12,15,20]),
        "R008": ("404",                                          "min_404s",      [10,15,20,25,30]),
        "R020": ("rdp|3389",                                     "min_failures",  [4,6,8,10,12,15]),
    }
    if rid in threshold_targets and raws:
        pattern, param, candidates = threshold_targets[rid]
        try:
            import json as _json
            with open(RULE_CONFIG) as f:
                rc = _json.load(f)
            current = rc.get(rid, {}).get(param, candidates[len(candidates)//2])
            opt = optimise_count_threshold(raws, benign_raws_sample, pattern, current, candidates)
            opt["current_threshold"] = current
            opt["param"] = param
            entry["threshold_optimisation"] = opt
            if opt["threshold"] != current:
                print(f"  📊 {rid}: {param} {current} → {opt['threshold']} "
                      f"(F1 {opt['f1']:.3f})")
        except Exception as exc:
            entry["threshold_optimisation"] = {"error": str(exc)}

    insights[rid] = entry

# ── Uncovered attacks: mine patterns for new rule candidates ─────────────────
print(f"\n  Mining patterns in {len(uncovered_raws):,} ML-only attack records …")
uncovered_patterns = top_patterns(uncovered_raws, top_n=25) if uncovered_raws else []

# ── Format coverage analysis ──────────────────────────────────────────────────
fmt_attack: Counter = Counter()
fmt_benign: Counter = Counter()
fmt_rule:   dict[str, Counter] = defaultdict(Counter)

for rec in attacks:
    fmt = rec.get("format", "unknown")
    fmt_attack[fmt] += 1
    for rid in (rec.get("rule_ids") or []):
        fmt_rule[fmt][rid] += 1
for rec in benign:
    fmt_benign[rec.get("format", "unknown")] += 1

format_coverage = {}
for fmt in set(list(fmt_attack.keys()) + list(fmt_benign.keys())):
    atk = fmt_attack[fmt]
    ben = fmt_benign[fmt]
    tot = atk + ben
    format_coverage[fmt] = {
        "total": tot,
        "attacks": atk,
        "benign": ben,
        "attack_ratio": round(atk / max(tot, 1), 3),
        "rules_seen": dict(fmt_rule[fmt].most_common(5)),
    }

# ── Write insights ────────────────────────────────────────────────────────────
output = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_summary": {
        "total_records": total,
        "attack_records": len(attacks),
        "benign_records": len(benign),
        "rules_with_samples": len(rule_samples),
        "uncovered_attack_records": len(uncovered_raws),
        "tactic_distribution": dict(tactic_counts.most_common()),
    },
    "rule_insights": insights,
    "uncovered_attack_patterns": uncovered_patterns,
    "format_coverage": format_coverage,
}

OUT.write_text(json.dumps(output, indent=2), encoding="utf-8")
size_kb = OUT.stat().st_size / 1024

print(f"\n  ✓ rule_insights.json written ({size_kb:.1f} KB)")
print(f"  Rules analysed: {len(insights)}")
print(f"  Uncovered attack patterns mined: {len(uncovered_patterns)}")
print()
print("  Top uncovered attack patterns (for new rule candidates):")
for p in uncovered_patterns[:10]:
    print(f"    [{p['lift']:>6.1f}x lift]  {p['pattern']}")
print()
print("  Threshold optimisation summary:")
for rid, ins in insights.items():
    opt = ins.get("threshold_optimisation")
    if opt and "threshold" in opt and opt.get("threshold") != opt.get("current_threshold"):
        param = opt.get("param", "?")
        print(f"    {rid}: {param} {opt['current_threshold']} → {opt['threshold']} "
              f"(F1={opt['f1']:.3f})")
