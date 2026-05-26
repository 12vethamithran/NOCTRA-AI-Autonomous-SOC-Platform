"""
gen_random.py  —  generates 5 random test log files for NOCTRA
Run:  python test_data/gen_random.py
"""
import random, json
from datetime import datetime, timezone, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent / "random_samples"
OUT.mkdir(exist_ok=True)

BASE_TIME = datetime(2026, 5, 26, 10, 0, 0, tzinfo=timezone.utc)

def ts(offset_s):
    return (BASE_TIME + timedelta(seconds=offset_s)).strftime("%b %d %H:%M:%S")

def iso(offset_s):
    return (BASE_TIME + timedelta(seconds=offset_s)).isoformat()

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSH brute force from two attackers  →  expects R001
# ─────────────────────────────────────────────────────────────────────────────
users = ["root", "admin", "ubuntu", "pi", "test", "oracle", "postgres"]
lines = []
t = 0
# 25 legit logins spread over 20 minutes
for _ in range(25):
    ip = "10.0.0." + str(random.randint(2, 50))
    u = random.choice(["alice", "bob", "charlie"])
    lines.append(
        f"{ts(t)} prod-srv sshd[{random.randint(1000,9999)}]: "
        f"Accepted publickey for {u} from {ip} port {random.randint(30000,65000)} ssh2"
    )
    t += random.randint(30, 120)

# Attacker 1 — 40 failures in ~55 s  (triggers R001)
t = 1000
for _ in range(40):
    u = random.choice(users)
    lines.append(
        f"{ts(t)} prod-srv sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {u} from 45.33.32.156 port {random.randint(30000,65000)} ssh2"
    )
    t += random.randint(1, 3)

# Attacker 2 — 15 failures spread over 5 min (below threshold, no alert)
t = 2000
for _ in range(15):
    u = random.choice(users)
    lines.append(
        f"{ts(t)} prod-srv sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {u} from 198.51.100.77 port {random.randint(30000,65000)} ssh2"
    )
    t += random.randint(15, 25)

# Sort chronologically and write
lines.sort(key=lambda l: l[:15])
(OUT / "random_ssh_multi_attacker.log").write_text("\n".join(lines), encoding="utf-8")
print("1. random_ssh_multi_attacker.log  — 2 attackers, 1 over threshold → R001")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Web attack — SQLi payloads + sqlmap scanner UA  →  expects R024 + R025
# ─────────────────────────────────────────────────────────────────────────────
log_lines = []
legit_ips = ["10.0.0." + str(i) for i in range(5, 30)]
t = 0

# 30 normal requests
for _ in range(30):
    ip = random.choice(legit_ips)
    path = random.choice(["/", "/about", "/products", "/contact", "/api/status"])
    sc = random.choice([200, 200, 200, 304, 301])
    sz = random.randint(500, 8000)
    h, m, s = 10 + t // 3600, (t % 3600) // 60, t % 60
    log_lines.append(
        f'{ip} - - [26/May/2026:{h:02d}:{m:02d}:{s:02d} +0000] '
        f'"GET {path} HTTP/1.1" {sc} {sz}'
    )
    t += random.randint(2, 15)

# SQLi payloads (R024)
atk = "185.220.101.55"
sqli_paths = [
    "/login?user=admin'%20OR%20'1'='1&pass=x",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/api/items?id=1%20AND%20SLEEP(5)--",
    "/products?cat=1;DROP%20TABLE%20orders--",
    "/report?date=2026-01-01'%20UNION%20ALL%20SELECT%20null,null--",
]
for path in sqli_paths:
    h, m, s = 10 + t // 3600, (t % 3600) // 60, t % 60
    log_lines.append(
        f'{atk} - - [26/May/2026:{h:02d}:{m:02d}:{s:02d} +0000] '
        f'"GET {path} HTTP/1.1" 200 1234'
    )
    t += 3

# sqlmap scanner UA (R025)
for path in ["/admin", "/wp-admin", "/.env", "/config.php", "/backup.zip"]:
    h, m, s = 10 + t // 3600, (t % 3600) // 60, t % 60
    log_lines.append(
        f'{atk} - - [26/May/2026:{h:02d}:{m:02d}:{s:02d} +0000] '
        f'"GET {path} HTTP/1.1" 404 0 "-" "sqlmap/1.7.8"'
    )
    t += 1

(OUT / "random_web_sqli_scan.log").write_text("\n".join(log_lines), encoding="utf-8")
print("2. random_web_sqli_scan.log       — SQLi + scanner UA → R024, R025")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Privilege escalation → LSASS dump → persistence → log clear
#    →  expects R013, R017, R018
# ─────────────────────────────────────────────────────────────────────────────
syslog = []
t = 0
# Normal session activity
for _ in range(20):
    h = random.choice(["workstation-01", "workstation-07", "dc-01"])
    u = random.choice(["alice", "bob", "carlos"])
    svc = random.choice(["sshd", "sudo", "cron", "systemd"])
    syslog.append(
        f"{ts(t)} {h} {svc}[{random.randint(500,9999)}]: session opened for user {u}"
    )
    t += random.randint(60, 300)

# Attack chain starting at t=5000
t = 5000
syslog.append(f"{ts(t)} workstation-07 sudo[4421]: alice : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash")
t += 8
syslog.append(f"{ts(t)} workstation-07 kernel[0]: comsvcs.dll, minidump lsass.exe C:\\Windows\\Temp\\lsass.dmp")
t += 3
syslog.append(f"{ts(t)} workstation-07 security[9999]: mimikatz executed — sekurlsa::logonpasswords")
t += 6
syslog.append(f"{ts(t)} workstation-07 cmd[5001]: schtasks /create /tn WindowsDefenderUpdate /tr C:\\tmp\\backdoor.exe /sc onlogon")
t += 4
syslog.append(f"{ts(t)} dc-01 EventLog[612]: EventID: 1102  The audit log was cleared.  Subject Account Name: alice")

syslog.sort(key=lambda x: x[:15])
(OUT / "random_escalation_chain.log").write_text("\n".join(syslog), encoding="utf-8")
print("3. random_escalation_chain.log    — LSASS + persistence + log clear → R013, R017, R018")

# ─────────────────────────────────────────────────────────────────────────────
# 4. C2 beaconing (very regular 30 s interval) + port scan
#    →  expects R021 (beacon) + R002 (port scan)
# ─────────────────────────────────────────────────────────────────────────────
c2_lines = []
# Background noise
for i in range(20):
    t2 = i * 15 + random.randint(0, 5)
    dst = f"10.0.0.{random.randint(1,20)}"
    c2_lines.append(
        f"time={iso(t2)} level=info src=192.168.5.100 dst={dst} "
        f"dport={random.randint(80,9000)} bytes={random.randint(100,2000)} msg=internal_request"
    )

# 12 beacons every ~30 s to external C2 IP (triggers R021)
for i in range(12):
    t2 = 1000 + i * 30 + random.randint(-1, 1)
    c2_lines.append(
        f"time={iso(t2)} level=warn src=192.168.5.100 dst=203.0.113.99 "
        f"dport=443 bytes={random.randint(200,400)} msg=egress_connection"
    )

# 18 distinct port probes in 30 s window (triggers R002)
port_t = 3000
for port in random.sample(range(20, 9000), 18):
    c2_lines.append(
        f"time={iso(port_t)} level=info src=192.168.5.100 dst=10.0.1.5 "
        f"dport={port} bytes=64 msg=tcp_probe"
    )
    port_t += 1

c2_lines.sort(key=lambda l: l.split(" ")[0])
(OUT / "random_c2_and_portscan.log").write_text("\n".join(c2_lines), encoding="utf-8")
print("4. random_c2_and_portscan.log     — C2 beacon + port scan → R021, R002")

# ─────────────────────────────────────────────────────────────────────────────
# 5. AWS CloudTrail-style JSON — recon + new admin  →  expects R007, R042
# ─────────────────────────────────────────────────────────────────────────────
aws_events = []
t = 0
legit_ops = ["GetObject", "PutObject", "ListBuckets", "DescribeInstances", "GetCallerIdentity"]

# 20 normal ops
for _ in range(20):
    aws_events.append(json.dumps({
        "timestamp": iso(t),
        "eventSource": "aws.amazon.com",
        "eventName": random.choice(legit_ops),
        "sourceIPAddress": f"203.0.{random.randint(100,120)}.{random.randint(1,254)}",
        "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
        "responseElements": {"status": "Success"},
    }))
    t += random.randint(30, 200)

# Cloud recon burst — many Describe/List calls (triggers R042)
recon_ops = [
    "DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs",
    "DescribeSubnets", "ListRoles", "ListUsers", "ListPolicies",
    "DescribeLoadBalancers", "DescribeDBInstances", "GetAccountAuthorizationDetails",
    "ListBuckets", "DescribeImages", "DescribeKeyPairs", "ListAccessKeys",
    "DescribeRouteTables", "DescribeNetworkInterfaces",
]
t = 3000
for op in recon_ops:
    aws_events.append(json.dumps({
        "timestamp": iso(t),
        "eventSource": "aws.amazon.com",
        "eventName": op,
        "sourceIPAddress": "185.220.101.200",
        "userIdentity": {"type": "IAMUser", "userName": "temp-analyst"},
        "responseElements": {"status": "Success"},
    }))
    t += random.randint(2, 8)

# New admin IAM user created (triggers R007)
aws_events.append(json.dumps({
    "timestamp": iso(t),
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateUser",
    "sourceIPAddress": "185.220.101.200",
    "userIdentity": {"type": "IAMUser", "userName": "temp-analyst"},
    "requestParameters": {"userName": "backdoor-admin"},
    "responseElements": {"status": "Success"},
    "user": "backdoor-admin",
    "event_type": "admin account created",
}))
t += 3
aws_events.append(json.dumps({
    "timestamp": iso(t),
    "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy",
    "sourceIPAddress": "185.220.101.200",
    "userIdentity": {"type": "IAMUser", "userName": "temp-analyst"},
    "requestParameters": {"userName": "backdoor-admin", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    "responseElements": {"status": "Success"},
    "user": "backdoor-admin",
}))

(OUT / "random_aws_recon_admin.json").write_text("\n".join(aws_events), encoding="utf-8")
print("5. random_aws_recon_admin.json    — cloud recon + new admin → R007, R042")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Pure benign office traffic — ZERO alerts expected
# ─────────────────────────────────────────────────────────────────────────────
benign = []
t = 0
office_users = ["alice@corp.com", "bob@corp.com", "charlie@corp.com", "diana@corp.com"]
for _ in range(80):
    u = random.choice(office_users)
    ip = f"10.10.{random.randint(0,5)}.{random.randint(2,254)}"
    action = random.choice(["FileRead", "FileWrite", "Login", "Logout", "EmailSent", "MeetingJoined", "DocumentViewed"])
    benign.append(json.dumps({
        "timestamp": iso(t),
        "user": u,
        "source_ip": ip,
        "action": action,
        "status": "Success",
        "bytes": random.randint(100, 50000),
        "dest_ip": f"10.0.0.{random.randint(1,10)}",
    }))
    t += random.randint(30, 600)

(OUT / "random_benign_office.json").write_text("\n".join(benign), encoding="utf-8")
print("6. random_benign_office.json      — 80 benign office events → 0 alerts")

print("\nDone. All files in test_data/random_samples/")
