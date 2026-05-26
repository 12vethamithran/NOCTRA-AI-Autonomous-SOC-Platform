"""Phase 1 verification — confirm directory structure and dependencies."""
import os, sys, importlib

BASE = os.path.dirname(__file__)

REQUIRED_DIRS = [
    "raw/evtx", "raw/syslog", "raw/csv_netflow",
    "raw/json_cloud", "raw/waf_web", "raw/pcap_zeek", "raw/multi_format",
    "normalized/labeled", "normalized/unlabeled", "schemas",
]

REQUIRED_FILES = ["manifest.json", "schemas/normalized_record.json"]

REQUIRED_PKGS = [
    ("Evtx.Evtx",  "python-evtx"),
    ("pandas",     "pandas"),
    ("tqdm",       "tqdm"),
    ("requests",   "requests"),
    ("yaml",       "pyyaml"),
    ("dateutil",   "python-dateutil"),
    ("faker",      "faker"),
]

ok = True

print("── Directory structure ───────────────────────────────")
for d in REQUIRED_DIRS:
    path = os.path.join(BASE, d)
    exists = os.path.isdir(path)
    print(f"  {'✓' if exists else '✗'} {d}")
    if not exists:
        ok = False

print("\n── Required files ────────────────────────────────────")
for f in REQUIRED_FILES:
    path = os.path.join(BASE, f)
    exists = os.path.isfile(path)
    print(f"  {'✓' if exists else '✗'} {f}")
    if not exists:
        ok = False

print("\n── Python dependencies ───────────────────────────────")
for mod, pkg in REQUIRED_PKGS:
    try:
        importlib.import_module(mod)
        print(f"  ✓ {pkg}")
    except ImportError:
        print(f"  ✗ {pkg}  (pip install {pkg})")
        ok = False

print("\n" + ("═" * 54))
if ok:
    print("  PHASE 1 COMPLETE — ready for Phase 2 (dataset fetch)")
else:
    print("  PHASE 1 INCOMPLETE — fix the items marked ✗ above")
    sys.exit(1)
