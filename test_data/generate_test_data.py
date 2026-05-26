"""
Generate NOCTRA test data sets — one file per attack scenario.
Run from the test_data/ directory:  python generate_test_data.py
"""
import json, random, os
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent
random.seed(99)

def ts(offset_min=0):
    base = datetime(2026, 5, 26, 2, 14, 0, tzinfo=timezone.utc)  # off-hours
    t = base + timedelta(minutes=offset_min, seconds=random.randint(0,59))
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def syslog_ts(offset_min=0):
    base = datetime(2026, 5, 26, 2, 14, 0, tzinfo=timezone.utc)
    t = base + timedelta(minutes=offset_min, seconds=random.randint(0,59))
    return t.strftime("%b %d %H:%M:%S")

ATTACKER = "185.220.101.47"
VICTIM   = "10.0.1.45"
BOT_IPS  = ["91.108.4.12", "77.88.55.60", "194.165.16.10", "45.83.64.100"]

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSH Brute Force  →  triggers R001 + ML Credential Access
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# 80 failed logins from same attacker IP (well above R001 threshold of 5)
for i in range(80):
    lines.append(f"{syslog_ts(i//10)} srv-web-01 sshd[1234]: Failed password for invalid user admin from {ATTACKER} port {40000+i} ssh2")
# sprinkle a success to make it realistic
lines.append(f"{syslog_ts(9)} srv-web-01 sshd[1234]: Accepted password for root from {ATTACKER} port 41337 ssh2")
# normal background traffic
for i in range(20):
    lines.append(f"{syslog_ts(i)} srv-web-01 sshd[999]: Accepted publickey for deploy from 10.0.0.5 port 5500{i} ssh2")

Path(OUT / "test_ssh_bruteforce.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_ssh_bruteforce.log  ({len(lines)} lines)")

# ─────────────────────────────────────────────────────────────────────────────
# 2. SQL Injection + Web Scanning  →  triggers R008 (404s) + R024 (SQLi) + ML
# ─────────────────────────────────────────────────────────────────────────────
lines = []
sqli_payloads = [
    "' OR 1=1--", "'; DROP TABLE users;--", "' UNION SELECT null,username,password FROM users--",
    "admin'--", "1' AND sleep(5)--", "' OR 'x'='x", "1; EXEC xp_cmdshell('whoami')--",
    "' UNION SELECT 1,2,3--", "'; INSERT INTO users VALUES('hacker','pass')--",
]
# Web fuzzing — 30 404s
for i in range(30):
    paths = ["/admin", "/.env", "/wp-admin", "/phpmyadmin", "/config.php", "/.git/config",
             "/backup.zip", "/api/v1/debug", "/server-status", "/actuator/env"]
    lines.append(f'{ATTACKER} - - [{syslog_ts(i//5)}] "GET {random.choice(paths)} HTTP/1.1" 404 162 "-" "sqlmap/1.7"')

# SQL injection attempts
for i, payload in enumerate(sqli_payloads * 3):
    import urllib.parse
    enc = urllib.parse.quote(payload)
    lines.append(f'{ATTACKER} - - [{syslog_ts(i)}] "GET /login?user={enc}&pass=x HTTP/1.1" 500 0 "-" "sqlmap/1.7"')

# Normal traffic mixed in
for i in range(15):
    lines.append(f'203.0.113.{i} - - [{syslog_ts(i)}] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"')

Path(OUT / "test_web_attack.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_web_attack.log      ({len(lines)} lines)")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Windows Privilege Escalation + Lateral Movement  →  R003, R004, R007 + ML
# ─────────────────────────────────────────────────────────────────────────────
events = []
# EventID 4625 — failed logins
for i in range(10):
    events.append({
        "TimeCreated": ts(i), "EventID": 4625, "Computer": "DC01",
        "SubjectUserName": "jsmith", "TargetUserName": "Administrator",
        "IpAddress": ATTACKER, "LogonType": 3,
        "message": f"An account failed to log on. Source: {ATTACKER}"
    })
# EventID 4720 — new account created
events.append({
    "TimeCreated": ts(12), "EventID": 4720, "Computer": "DC01",
    "SubjectUserName": "jsmith", "TargetUserName": "hacker_backdoor",
    "message": "A user account was created."
})
# EventID 4732 — added to Administrators
events.append({
    "TimeCreated": ts(13), "EventID": 4732, "Computer": "DC01",
    "SubjectUserName": "jsmith", "TargetUserName": "hacker_backdoor",
    "GroupName": "Administrators",
    "message": "A member was added to a security-enabled local group. Group: Administrators"
})
# EventID 4624 — lateral movement (same user, 4 hosts, <5 min)
for i, host in enumerate(["SRV-HR-01","SRV-FIN-02","SRV-DEV-03","SRV-MGMT-04"]):
    events.append({
        "TimeCreated": ts(i), "EventID": 4624, "Computer": host,
        "SubjectUserName": "hacker_backdoor", "IpAddress": ATTACKER,
        "LogonType": 3,
        "message": f"Successful logon. User: hacker_backdoor Source: {ATTACKER} Host: {host}"
    })
# EventID 4688 — mimikatz process
events.append({
    "TimeCreated": ts(20), "EventID": 4688, "Computer": "DC01",
    "NewProcessName": "mimikatz.exe", "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
    "SubjectUserName": "hacker_backdoor",
    "message": "Process created: mimikatz.exe privilege::debug sekurlsa::logonpasswords"
})
# Normal events
for i in range(10):
    events.append({
        "TimeCreated": ts(i*3), "EventID": 4624, "Computer": "WS-01",
        "SubjectUserName": f"user{i:02d}", "IpAddress": "10.0.0.10",
        "LogonType": 2, "message": f"Normal interactive logon for user{i:02d}"
    })

Path(OUT / "test_windows_attack.json").write_text(
    "\n".join(json.dumps(e) for e in events), encoding="utf-8"
)
print(f"✓ test_windows_attack.json ({len(events)} events)")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Data Exfiltration (large outbound)  →  R005 + ML Exfiltration
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# Large outbound transfers to external IP (>100MB threshold)
for i in range(20):
    mb = random.randint(50, 200)
    lines.append(
        f"{ts(i)} FIREWALL ALLOW outbound src=10.0.1.45 dst={ATTACKER} "
        f"proto=TCP dport=443 bytes_out={mb*1024*1024} bytes_in=512 "
        f"app=HTTPS duration=300 action=allow"
    )
# DLP violation events
for i in range(5):
    lines.append(
        f"{ts(i*2)} DLP BLOCK user=jsmith src=10.0.1.45 dst={ATTACKER} "
        f"violation=credit_card file=customer_export_{i}.csv "
        f"bytes={random.randint(1,10)*1024*1024} severity=high"
    )
# Normal traffic
for i in range(10):
    lines.append(
        f"{ts(i)} FIREWALL ALLOW outbound src=10.0.0.{i+5} dst=8.8.8.8 "
        f"proto=UDP dport=53 bytes_out=256 bytes_in=128 action=allow"
    )

Path(OUT / "test_exfiltration.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_exfiltration.log    ({len(lines)} lines)")

# ─────────────────────────────────────────────────────────────────────────────
# 5. Cloud / AWS Attack (CloudTrail)  →  R020, R030, R037, R038 + ML
# ─────────────────────────────────────────────────────────────────────────────
cloud_events = []
# Console login failure then success (credential stuffing)
for i in range(8):
    cloud_events.append({
        "eventTime": ts(i), "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
        "userAgent": "python-boto3/1.26", "errorCode": "Failed authentication",
        "userIdentity": {"type": "IAMUser", "userName": "admin"},
        "responseElements": {"ConsoleLogin": "Failure"},
        "message": f"ConsoleLogin Failure from {ATTACKER}"
    })
cloud_events.append({
    "eventTime": ts(10), "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "responseElements": {"ConsoleLogin": "Success"},
    "message": f"ConsoleLogin Success from {ATTACKER} — suspicious after 8 failures"
})
# Privilege escalation — create access key + attach admin policy
cloud_events.append({
    "eventTime": ts(11), "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "requestParameters": {"userName": "backdoor_svc"},
    "sourceIPAddress": ATTACKER,
    "message": "CreateAccessKey for backdoor_svc without MFA"
})
cloud_events.append({
    "eventTime": ts(12), "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy",
    "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "backdoor_svc"},
    "sourceIPAddress": ATTACKER,
    "message": "AttachUserPolicy AdministratorAccess to backdoor_svc"
})
# CloudTrail disabled
cloud_events.append({
    "eventTime": ts(13), "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "requestParameters": {"name": "prod-trail"},
    "sourceIPAddress": ATTACKER,
    "message": "StopLogging — CloudTrail disabled by attacker"
})
# S3 mass download
for i in range(15):
    cloud_events.append({
        "eventTime": ts(14+i), "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "requestParameters": {"bucketName": "prod-customer-data", "key": f"customers_{i:04d}.csv"},
        "sourceIPAddress": ATTACKER,
        "userIdentity": {"type": "IAMUser", "userName": "backdoor_svc"},
        "message": f"S3 GetObject customers_{i:04d}.csv"
    })
# Normal events
for i in range(5):
    cloud_events.append({
        "eventTime": ts(i*5), "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "sourceIPAddress": "10.0.0.5",
        "userIdentity": {"type": "IAMUser", "userName": "devops_bot"},
        "message": "Normal EC2 DescribeInstances by devops_bot"
    })

Path(OUT / "test_aws_attack.json").write_text(
    "\n".join(json.dumps(e) for e in cloud_events), encoding="utf-8"
)
print(f"✓ test_aws_attack.json     ({len(cloud_events)} events)")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Port Scan + C2 Beaconing  →  R002 + R021 + ML
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# Port scan — 40 distinct ports in 30s
for port in range(20, 60):
    lines.append(
        f"{ts(0)} FIREWALL DENY inbound src={ATTACKER} dst={VICTIM} "
        f"proto=TCP dport={port} flags=SYN bytes=64 action=deny"
    )
# C2 beaconing — regular interval (every 60s = textbook beacon)
for i in range(30):
    lines.append(
        f"{ts(i)} FIREWALL ALLOW outbound src={VICTIM} dst={ATTACKER} "
        f"proto=TCP dport=4444 bytes_out=256 bytes_in=1024 action=allow interval=60s"
    )
# DNS tunneling signs
for i in range(15):
    subdomain = f"{''.join(random.choices('abcdef0123456789', k=32))}.evil-c2.com"
    lines.append(
        f"{ts(i*2)} DNS QUERY src={VICTIM} qtype=TXT query={subdomain} "
        f"response=NXDOMAIN"
    )
# Normal traffic
for i in range(10):
    lines.append(
        f"{ts(i*3)} FIREWALL ALLOW outbound src=10.0.0.{i+5} dst=1.1.1.1 "
        f"proto=UDP dport=53 bytes_out=100 bytes_in=200 action=allow"
    )

Path(OUT / "test_c2_beacon.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_c2_beacon.log       ({len(lines)} lines)")

# ─────────────────────────────────────────────────────────────────────────────
# 7. Benign-only (should produce zero or near-zero alerts) — FP check
# ─────────────────────────────────────────────────────────────────────────────
lines = []
for i in range(50):
    lines.append(
        f"{syslog_ts(i)} srv-web-01 sshd[100]: Accepted publickey for deploy "
        f"from 10.0.0.5 port 5000{i} ssh2"
    )
    lines.append(
        f"203.0.113.{i%254+1} - - [{syslog_ts(i)}] "
        f'"GET /api/health HTTP/1.1" 200 42 "-" "HealthChecker/2.0"'
    )
for i in range(20):
    lines.append(
        f"{ts(i*5)} FIREWALL ALLOW outbound src=10.0.0.10 dst=8.8.8.8 "
        f"proto=UDP dport=53 bytes_out=80 bytes_in=180 action=allow"
    )

Path(OUT / "test_benign_only.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_benign_only.log     ({len(lines)} lines)")

# ─────────────────────────────────────────────────────────────────────────────
# 8. Mixed / Realistic (all attack types in one file) — ultimate stress test
# ─────────────────────────────────────────────────────────────────────────────
mixed = []
# SSH brute
for i in range(25): mixed.append(f"{syslog_ts(i//5)} srv-01 sshd[1]: Failed password for root from {ATTACKER} port {5000+i} ssh2")
# Web SQLi
for i in range(10): mixed.append(f'{ATTACKER} - - [{syslog_ts(i)}] "GET /login?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" 500 0')
# Mimikatz
mixed.append(f"{syslog_ts(20)} DC01 Security: EventID=4688 NewProcessName=mimikatz.exe CommandLine=sekurlsa::logonpasswords SubjectUserName=jsmith")
# Exfil
for i in range(5): mixed.append(f"{ts(i)} DLP BLOCK user=jsmith dst={ATTACKER} file=ssn_dump_{i}.csv bytes=5242880 severity=critical violation=ssn")
# CloudTrail
mixed.append(json.dumps({"eventTime": ts(25), "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com", "sourceIPAddress": ATTACKER, "message": "CloudTrail StopLogging"}))
mixed.append(json.dumps({"eventTime": ts(26), "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com", "sourceIPAddress": ATTACKER, "requestParameters": {"userName": "shadow_admin"}, "message": "CreateAccessKey shadow_admin without MFA"}))
# Beacon
for i in range(10): mixed.append(f"{ts(i)} FIREWALL ALLOW outbound src={VICTIM} dst={ATTACKER} dport=4444 bytes_out=256 bytes_in=1024 action=allow")
# Normal noise
for i in range(30): mixed.append(f'{syslog_ts(i)} srv-01 sshd[2]: Accepted publickey for deploy from 10.0.0.5 port 4000{i} ssh2')

random.shuffle(mixed)
Path(OUT / "test_mixed_realistic.log").write_text("\n".join(mixed), encoding="utf-8")
print(f"✓ test_mixed_realistic.log ({len(mixed)} lines)")

print()
print("━"*60)
print(f"  All test files written to: {OUT}")
print("━"*60)
print("""
  FILE                        EXPECTED ALERTS
  ──────────────────────────  ──────────────────────────────────────────
  test_ssh_bruteforce.log     R001 Brute Force · ML Credential Access
  test_web_attack.log         R008 404 Fuzzing · R024 SQLi · ML Initial Access
  test_windows_attack.json    R003 PrivEsc · R004 Lateral · R007 New Admin · ML
  test_exfiltration.log       R005 Data Exfil · ML Exfiltration
  test_aws_attack.json        R020 RDP Brute · R030 Cloud Role · R037 No-MFA · R038 CloudTrail
  test_c2_beacon.log          R002 Port Scan · R021 C2 Beaconing · ML C2
  test_benign_only.log        ✅  0 alerts (false-positive check)
  test_mixed_realistic.log    ALL of the above combined
""")
