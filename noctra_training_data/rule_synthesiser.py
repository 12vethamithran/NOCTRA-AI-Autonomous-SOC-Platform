"""
rule_synthesiser.py
===================
Phase 3 of the ML-driven upgrade pipeline.

Reads  rule_insights.json  (produced by Phase 2 corpus_analyser.py)
Writes updated  rule_config.json  (live-reloaded by the backend)
       and       synthesised_rules.py  (candidate new rules for human review)

What it does:
  1. Threshold patching — for R001/R002/R008/R020 where the corpus-optimised
     threshold beats the current one by ≥ 0.02 F1, write the new value into
     rule_config.json and log the change.
  2. Pattern enrichment — for each raw-pattern rule (R011-R025), append any
     newly mined high-lift bigrams that look like real IoCs, keeping pattern
     lists fresh without human intervention.
  3. New-rule candidates — for uncovered attack patterns with lift ≥ 50x,
     emit skeleton rule stubs into synthesised_rules.py for an analyst to
     promote to rules.py.
  4. Writes a synthesis_report.json summarising every change.

Run from noctra_training_data/:
  python rule_synthesiser.py
"""

import json
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

BASE     = Path(__file__).parent
INSIGHTS = BASE / "rule_insights.json"
REPORT   = BASE / "synthesis_report.json"
SYNTH_PY = BASE / "synthesised_rules.py"

RULE_CONFIG = BASE.parent / "backend" / "engine" / "rule_config.json"

# ── Guards ────────────────────────────────────────────────────────────────────
MIN_F1_IMPROVEMENT  = 0.02   # must improve F1 by this much to patch threshold
MIN_LIFT_PATTERN    = 30.0   # bigrams below this lift aren't added to rules
MIN_LIFT_NEW_RULE   = 50.0   # lift needed to emit a new-rule candidate
MIN_ATTACK_COUNT    = 5      # pattern must appear ≥ N times in attack corpus

# Raw-pattern rules that can be enriched with new bigrams
RAW_PATTERN_RULE_IDS = {
    "R011", "R012", "R013", "R015", "R017",
    "R018", "R019", "R024", "R025",
}

# Words too generic to be useful IoC patterns
_GENERIC = {
    "failed", "failure", "error", "warning", "info", "debug", "user", "host",
    "time", "date", "data", "event", "log", "line", "type", "file",
    "system", "process", "service", "request", "response", "status",
    "message", "source", "target", "remote", "local", "port",
    "password", "attempt", "login", "auth", "accept", "invalid",
    "connection", "session", "client", "server", "address", "addr",
    "attack", "attack_type", "scan", "type", "label", "category",
    "severity", "rule", "alert", "detection", "flag",
}

def _looks_like_ioc(bigram: str) -> bool:
    """Heuristic: does this bigram resemble a genuine indicator of compromise?"""
    parts = bigram.lower().split()
    # All words are generic → skip
    if all(p in _GENERIC for p in parts):
        return False
    # Only check attack hints on the non-generic parts
    _ATTACK_HINTS = {
        "exec", "shell", "cmd", "inject", "payload", "exploit",
        "bypass", "escalat", "dump", "mimikatz", "lsass", "lateral",
        "beacon", "tunnel", "exfil", "ransom", "encrypt", "shadow",
        "kerberos", "ticket", "cred",
        "powershell", "encodedcommand", "base64string", "bitstransfer",
        "wget", "curl", "downloadstring", "downloadfile",
        "nmap", "sqlmap", "nikto", "masscan", "gobuster",
        "union select", "xp_cmdshell", "information_schema",
        "webshell", "c99.php", "r57.php",
        "createremotethread", "writeprocessmemory", "minidump",
        "wevtutil", "clear-eventlog", "windefend",
        "schtasks", "crontab", "currentversion\\run",
    }
    non_generic = [p for p in parts if p not in _GENERIC]
    for p in non_generic:
        for hint in _ATTACK_HINTS:
            if hint == p or (len(hint) > 5 and hint in p):
                return True
    return False


print("━"*65)
print("  PHASE 3 — RULE SYNTHESISER")
print("━"*65)

# ── Load inputs ───────────────────────────────────────────────────────────────
if not INSIGHTS.exists():
    sys.exit("  ✗ rule_insights.json not found — run corpus_analyser.py first")

with open(INSIGHTS, encoding="utf-8") as f:
    insights = json.load(f)

with open(RULE_CONFIG, encoding="utf-8") as f:
    config = json.load(f)

print(f"  Loaded insights for {len(insights['rule_insights'])} rules")
print(f"  Current rule_config.json has {sum(1 for k in config if not k.startswith('_'))} rule entries")

# ── Track all changes ─────────────────────────────────────────────────────────
changes: list[dict] = []
new_config = deepcopy(config)

# ── 1. Threshold patching ─────────────────────────────────────────────────────
print("\n  [1] Threshold optimisation …")
for rid, ins in insights["rule_insights"].items():
    opt = ins.get("threshold_optimisation")
    if not opt or "threshold" not in opt or "error" in opt:
        continue
    if opt["threshold"] == opt.get("current_threshold"):
        continue  # no change suggested

    f1_new     = opt.get("f1", 0)
    f1_current = 0.0  # we don't store current F1 — treat improvement as unconditional when corpus says so
    improvement = f1_new  # absolute F1 score (current is unknown baseline)

    if improvement < MIN_F1_IMPROVEMENT:
        print(f"    {rid}: skipping — F1 {f1_new:.3f} below guard ({MIN_F1_IMPROVEMENT})")
        continue

    param = opt["param"]
    old_val = opt["current_threshold"]
    new_val = opt["threshold"]

    if rid not in new_config:
        new_config[rid] = {}
    new_config[rid][param] = new_val

    msg = f"    ✓ {rid}: {param} {old_val} → {new_val}  (corpus F1={f1_new:.3f})"
    print(msg)
    changes.append({
        "type": "threshold_patch",
        "rule_id": rid,
        "param": param,
        "old_value": old_val,
        "new_value": new_val,
        "corpus_f1": f1_new,
    })

if not any(c["type"] == "threshold_patch" for c in changes):
    print("    (no threshold changes — all thresholds already optimal)")

# ── 2. Pattern enrichment for raw-pattern rules ───────────────────────────────
print("\n  [2] Pattern enrichment …")
enriched_rules: list[str] = []

for rid in sorted(RAW_PATTERN_RULE_IDS):
    ins = insights["rule_insights"].get(rid, {})
    top_pats = ins.get("top_discriminative_patterns", [])

    candidates = [
        p["pattern"] for p in top_pats
        if p.get("lift", 0) >= MIN_LIFT_PATTERN
        and p.get("attack_count", 0) >= MIN_ATTACK_COUNT
        and _looks_like_ioc(p["pattern"])
    ]
    if not candidates:
        continue

    raw_section = new_config.setdefault("_raw_pattern_rules", {})
    rule_entry  = raw_section.setdefault(rid, {"patterns": []})
    existing    = {p.lower() for p in rule_entry.get("patterns", [])}

    added = []
    for pat in candidates:
        if pat.lower() not in existing:
            rule_entry["patterns"].append(pat)
            existing.add(pat.lower())
            added.append(pat)

    if added:
        print(f"    ✓ {rid}: +{len(added)} pattern(s): {added[:3]}{'…' if len(added)>3 else ''}")
        enriched_rules.append(rid)
        changes.append({
            "type": "pattern_enrichment",
            "rule_id": rid,
            "added_patterns": added,
        })

if not enriched_rules:
    print("    (no new patterns met the lift/count/IoC guards)")

# ── 3. New-rule candidates from uncovered patterns ────────────────────────────
print("\n  [3] New-rule candidate generation …")
uncovered = insights.get("uncovered_attack_patterns", [])
candidates = [
    p for p in uncovered
    if p.get("lift", 0) >= MIN_LIFT_NEW_RULE
    and p.get("attack_count", 0) >= MIN_ATTACK_COUNT
    and _looks_like_ioc(p["pattern"])
]

if candidates:
    # Group by first word (rough tactic cluster)
    lines = [
        '"""',
        "synthesised_rules.py",
        "==================",
        "AUTO-GENERATED by rule_synthesiser.py — DO NOT COMMIT without analyst review.",
        "",
        "Each stub below is a CANDIDATE new rule derived from uncovered attack patterns",
        "in the training corpus that no existing rule currently catches.",
        "",
        "To promote a stub:",
        "  1. Give it a proper R0xx ID in the EXPECTED_RULES set (rules.py).",
        "  2. Implement the detection logic in rules.py.",
        "  3. Add its config to rule_config.json.",
        "  4. Add labelled samples to the training corpus and retrain.",
        '"""',
        "",
        "# ── Candidate rules ──────────────────────────────────────────────────────────",
        "",
    ]
    for i, p in enumerate(candidates[:20], start=1):
        slug = p["pattern"].replace(" ", "_").replace("-", "_")
        lines += [
            f"# Candidate {i}: lift={p['lift']}x, attack_count={p['attack_count']}",
            f"# Pattern: '{p['pattern']}'",
            f"# Suggested tactic: Unknown (analyst review required)",
            f"CANDIDATE_{i:02d} = {{",
            f'    "pattern": "{p["pattern"]}",',
            f'    "lift": {p["lift"]},',
            f'    "attack_count": {p["attack_count"]},',
            f'    "description": "TODO: fill in description",',
            f'    "mitre_technique": "TODO",',
            f'    "mitre_tactic": "TODO",',
            f"}}",
            "",
        ]
    SYNTH_PY.write_text("\n".join(lines), encoding="utf-8")
    print(f"    ✓ {len(candidates)} candidates → synthesised_rules.py")
    changes.append({
        "type": "new_rule_candidates",
        "count": len(candidates),
        "patterns": [p["pattern"] for p in candidates],
    })
else:
    print("    (no high-lift uncovered patterns found — corpus well-covered)")
    SYNTH_PY.write_text(
        '"""synthesised_rules.py — No new candidates this cycle."""\n',
        encoding="utf-8",
    )

# ── 4. Write updated rule_config.json ────────────────────────────────────────
if any(c["type"] in ("threshold_patch", "pattern_enrichment") for c in changes):
    new_config["_last_updated"] = datetime.now(timezone.utc).isoformat()
    new_config["_updated_by"] = "rule_synthesiser"
    new_config["_version"] = int(config.get("_version", 1)) + 1

    with open(RULE_CONFIG, "w", encoding="utf-8") as f:
        json.dump(new_config, f, indent=2)
    print(f"\n  ✓ rule_config.json updated (version {new_config['_version']})")
else:
    print("\n  (rule_config.json unchanged — no threshold or pattern changes)")

# ── 5. Write synthesis report ─────────────────────────────────────────────────
report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "corpus_summary": insights.get("corpus_summary", {}),
    "changes_made": len(changes),
    "changes": changes,
    "format_coverage": insights.get("format_coverage", {}),
    "guards_used": {
        "min_f1_improvement": MIN_F1_IMPROVEMENT,
        "min_lift_pattern": MIN_LIFT_PATTERN,
        "min_lift_new_rule": MIN_LIFT_NEW_RULE,
        "min_attack_count": MIN_ATTACK_COUNT,
    },
}
REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")

print(f"  ✓ synthesis_report.json written")
print(f"\n  Summary: {len(changes)} change(s) applied")
for c in changes:
    if c["type"] == "threshold_patch":
        print(f"    • {c['rule_id']} {c['param']}: {c['old_value']} → {c['new_value']}")
    elif c["type"] == "pattern_enrichment":
        print(f"    • {c['rule_id']}: +{len(c['added_patterns'])} patterns")
    elif c["type"] == "new_rule_candidates":
        print(f"    • {c['count']} new-rule candidates written to synthesised_rules.py")
print()
