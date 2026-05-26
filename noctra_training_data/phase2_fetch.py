"""
Phase 2 — Fetch public security log datasets.
Handles failures gracefully: logs errors to errors.log and continues.
Uses sparse/shallow clones to avoid downloading multi-GB repos.
"""
import os, sys, subprocess, requests, shutil, time, json
from pathlib import Path
from datetime import datetime

BASE   = Path(__file__).parent
RAW    = BASE / "raw"
ERRORS = BASE / "errors.log"

def log_err(source: str, msg: str):
    with open(ERRORS, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] PHASE2 | {source} | {msg}\n")
    print(f"  ✗ SKIP: {source} — {msg}")

def banner(msg: str):
    print(f"\n{'━'*60}\n  {msg}\n{'━'*60}")

def run(cmd: list[str], cwd=None, timeout=300) -> bool:
    try:
        r = subprocess.run(cmd, cwd=cwd, timeout=timeout,
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, r.stderr[:400]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)

def sparse_clone(url: str, dest: Path, folders: list[str], depth=1) -> bool:
    """Shallow sparse-checkout clone — only downloads the specified folders."""
    if dest.exists() and any(dest.iterdir()):
        print(f"  ↩  already cloned: {dest.name}")
        return True
    dest.mkdir(parents=True, exist_ok=True)
    cmds = [
        ["git", "clone", "--depth", str(depth), "--filter=blob:none",
         "--sparse", url, str(dest)],
    ]
    ok, err = run(cmds[0], timeout=180)
    if not ok:
        log_err(url, f"clone failed: {err}")
        shutil.rmtree(dest, ignore_errors=True)
        return False
    if folders:
        ok, err = run(["git", "sparse-checkout", "set"] + folders, cwd=dest, timeout=60)
        if not ok:
            log_err(url, f"sparse-checkout failed: {err}")
            # don't delete — we got something at least
    return True

def download_file(url: str, dest: Path, label: str) -> bool:
    """Download a single file via requests."""
    if dest.exists() and dest.stat().st_size > 100:
        print(f"  ↩  already downloaded: {dest.name}")
        return True
    try:
        r = requests.get(url, timeout=60, stream=True,
                         headers={"User-Agent": "NOCTRA-Training/1.0"})
        r.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        size_kb = dest.stat().st_size // 1024
        print(f"  ✓ {label} ({size_kb} KB) → {dest.name}")
        return True
    except Exception as e:
        log_err(label, str(e))
        return False

# ─────────────────────────────────────────────────────────────────────────────
# EVTX datasets
# ─────────────────────────────────────────────────────────────────────────────
banner("EVTX DATASETS")

# 1. EVTX-ATTACK-SAMPLES (sbousseaden)
evtx1 = RAW / "evtx" / "evtx-attack-samples"
ok = sparse_clone(
    "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
    evtx1,
    ["Defense%20Evasion", "Credential%20Access",
     "Lateral%20Movement", "Execution", "Persistence"],
)
if ok: print(f"  ✓ EVTX-ATTACK-SAMPLES → {evtx1}")

# 2. OTRF Security-Datasets (windows atomic)
evtx2 = RAW / "evtx" / "security-datasets"
ok = sparse_clone(
    "https://github.com/OTRF/Security-Datasets",
    evtx2,
    ["datasets/atomic/windows", "datasets/compound"],
    depth=1,
)
if ok: print(f"  ✓ Security-Datasets → {evtx2}")

# 3. evtx-baseline (Nextron)
evtx3 = RAW / "evtx" / "evtx-baseline"
ok = sparse_clone(
    "https://github.com/NextronSystems/evtx-baseline",
    evtx3,
    [],
    depth=1,
)
if ok: print(f"  ✓ evtx-baseline → {evtx3}")

# 4. DeepBlueCLI evtx samples
evtx4 = RAW / "evtx" / "deepbluecli"
ok = sparse_clone(
    "https://github.com/sans-blue-team/DeepBlueCLI",
    evtx4,
    ["evtx"],
    depth=1,
)
if ok: print(f"  ✓ DeepBlueCLI/evtx → {evtx4}")

# ─────────────────────────────────────────────────────────────────────────────
# SYSLOG / AUTH LOG datasets (LogHub samples)
# ─────────────────────────────────────────────────────────────────────────────
banner("SYSLOG / AUTH LOG DATASETS")

loghub = RAW / "syslog" / "loghub"
ok = sparse_clone(
    "https://github.com/logpai/loghub",
    loghub,
    ["Linux", "OpenSSH", "Apache", "Windows", "Mac"],
    depth=1,
)
if ok: print(f"  ✓ LogHub samples → {loghub}")

# Direct download of 2k sample log files from LogHub
LOGHUB_SAMPLES = [
    ("Linux/Linux_2k.log",      "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log"),
    ("OpenSSH/SSH_2k.log",      "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/SSH_2k.log"),
    ("Apache/Apache_2k.log",    "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log"),
]
for fname, url in LOGHUB_SAMPLES:
    dest = RAW / "syslog" / Path(fname).name
    download_file(url, dest, fname)

# ─────────────────────────────────────────────────────────────────────────────
# JSON / CLOUD datasets
# ─────────────────────────────────────────────────────────────────────────────
banner("JSON / CLOUD DATASETS")

# Elastic detection-rules test logs
elastic_dr = RAW / "json_cloud" / "elastic-detection-rules"
ok = sparse_clone(
    "https://github.com/elastic/detection-rules",
    elastic_dr,
    ["tests/files/logs", "tests/files/"],
    depth=1,
)
if ok: print(f"  ✓ elastic/detection-rules → {elastic_dr}")

# Azure Sentinel sample data
azure = RAW / "json_cloud" / "azure-sentinel"
ok = sparse_clone(
    "https://github.com/Azure/Azure-Sentinel",
    azure,
    ["Sample Data"],
    depth=1,
)
if ok: print(f"  ✓ Azure-Sentinel/Sample Data → {azure}")

# ─────────────────────────────────────────────────────────────────────────────
# WAF / WEB LOG datasets
# ─────────────────────────────────────────────────────────────────────────────
banner("WAF / WEB LOG DATASETS")

# Elastic examples — apache logs
elastic_ex = RAW / "waf_web" / "elastic-examples"
ok = sparse_clone(
    "https://github.com/elastic/examples",
    elastic_ex,
    ["Common%20Data%20Formats/apache_logs",
     "ElasticStack-getting-started/apache_logs"],
    depth=1,
)
if ok: print(f"  ✓ elastic/examples apache_logs → {elastic_ex}")

# LogHub Apache 2k sample
download_file(
    "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log",
    RAW / "waf_web" / "apache_2k.log",
    "LogHub/Apache_2k.log"
)

# LogHub nginx — try to get it
download_file(
    "https://raw.githubusercontent.com/logpai/loghub/master/Nginx/Nginx_2k.log",
    RAW / "waf_web" / "nginx_2k.log",
    "LogHub/Nginx_2k.log"
)

# ─────────────────────────────────────────────────────────────────────────────
# CSV / NetFlow datasets (direct download)
# ─────────────────────────────────────────────────────────────────────────────
banner("CSV / NETFLOW DATASETS (NSL-KDD)")

NSL_KDD_BASE = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
nsl_files = [
    ("KDDTrain+.txt",     f"{NSL_KDD_BASE}/KDDTrain%2B.txt"),
    ("KDDTest+.txt",      f"{NSL_KDD_BASE}/KDDTest%2B.txt"),
    ("Field_Names.csv",   f"{NSL_KDD_BASE}/Field%20Names.csv"),
]
for fname, url in nsl_files:
    download_file(url, RAW / "csv_netflow" / fname, f"NSL-KDD/{fname}")

# ─────────────────────────────────────────────────────────────────────────────
# MULTI-FORMAT — OTRF compound datasets
# ─────────────────────────────────────────────────────────────────────────────
banner("MULTI-FORMAT DATASETS")

otrf_compound = RAW / "multi_format" / "otrf-compound"
ok = sparse_clone(
    "https://github.com/OTRF/Security-Datasets",
    otrf_compound,
    ["datasets/compound"],
    depth=1,
)
if ok: print(f"  ✓ OTRF compound datasets → {otrf_compound}")

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
banner("PHASE 2 SUMMARY")

total_files = sum(1 for _ in RAW.rglob("*") if _.is_file() and _.name != ".gitkeep")
total_size  = sum(f.stat().st_size for f in RAW.rglob("*") if f.is_file()) / (1024*1024)

by_dir = {}
for d in ["evtx", "syslog", "csv_netflow", "json_cloud", "waf_web", "pcap_zeek", "multi_format"]:
    p = RAW / d
    files = [f for f in p.rglob("*") if f.is_file() and f.name != ".gitkeep"]
    by_dir[d] = len(files)

print(f"\n  Files fetched   : {total_files}")
print(f"  Total size      : {total_size:.1f} MB")
print(f"\n  Per directory:")
for d, n in by_dir.items():
    print(f"    {d:<20} {n:>5} files")

err_count = 0
if ERRORS.exists():
    lines = [l for l in ERRORS.read_text().splitlines() if "PHASE2" in l]
    err_count = len(lines)
print(f"\n  Fetch errors    : {err_count} (see errors.log)")
print("\n  ✓ Phase 2 complete — proceed to Phase 3 (synthetic generation)")
