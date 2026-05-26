"""
Generate NOCTRA test data — fixed version.
Key fixes:
  - Logs are chronological (rules use time-window sliding scans)
  - Attack events are tightly clustered within the rule thresholds
  - Each file uses ONE consistent format so the parser extracts columns properly
  - Mixed file uses syslog format throughout (no format confusion)
"""
import json, random, os
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent
random.seed(42)

BASE_TS = datetime(2026, 5, 26, 2, 0, 0, tzinfo=timezone.utc)  # 02:00 UTC (off-hours)

def ts(seconds_offset=0):
    t = BASE_TS + timedelta(seconds=seconds_offset)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def syslog_ts(seconds_offset=0):
    t = BASE_TS + timedelta(seconds=seconds_offset)
    return t.strftime("%b %d %H:%M:%S")

ATTACKER = "185.220.101.47"
VICTIM   = "10.0.1.45"
INTERNAL = "10.0.0.5"

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSH Brute Force — syslog format
#    R001: >5 failed logins from same IP within 60s
#    Trigger: 60 failures in 45 seconds
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# 60 failures from attacker, all within 45 seconds → definitely triggers R001
for i in range(60):
    lines.append(f"{syslog_ts(i)} srv-web-01 sshd[1234]: Failed password for invalid user admin from {ATTACKER} port {40000+i} ssh2")
# Attacker gets in
lines.append(f"{syslog_ts(46)} srv-web-01 sshd[1234]: Accepted password for root from {ATTACKER} port 41337 ssh2")
# Normal background (different IPs, different users)
for i in range(10):
    lines.append(f"{syslog_ts(100+i*10)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")

Path(OUT / "test_ssh_bruteforce.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_ssh_bruteforce.log     {len(lines):>4} lines  | expect: R001 Brute Force (CRITICAL)")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Web Attack — Apache access log format
#    R008: >20 HTTP 404s from same IP (fuzzing)
#    R024: SQL injection patterns
# ─────────────────────────────────────────────────────────────────────────────
import urllib.parse
lines = []
# 30 consecutive 404s from attacker (fuzzing)
fuzz_paths = ["/.env","/.git/config","/admin","/wp-admin","/phpmyadmin",
              "/config.php","/backup.zip","/.htaccess","/server-status",
              "/actuator/env","/api/v1/debug","/shell.php","/cmd.php"]
for i in range(30):
    path = fuzz_paths[i % len(fuzz_paths)]
    lines.append(f'{ATTACKER} - - [{syslog_ts(i*2)}] "GET {path} HTTP/1.1" 404 162 "-" "sqlmap/1.7.8"')

# SQL injection payloads
sqli = [
    "' OR 1=1--", "' UNION SELECT null,username,password FROM users--",
    "'; DROP TABLE users;--", "1' AND sleep(5)--",
    "' OR 'x'='x", "1; EXEC xp_cmdshell('whoami')--",
    "admin'--", "' UNION SELECT 1,2,3--",
    "1 AND 1=1 UNION SELECT ALL SELECT NULL--",
    "' OR 1=1 LIMIT 1 OFFSET 1--",
]
for i, payload in enumerate(sqli * 4):
    enc = urllib.parse.quote(payload)
    lines.append(f'{ATTACKER} - - [{syslog_ts(60+i*3)}] "GET /login?user={enc}&pass=x HTTP/1.1" 500 0 "-" "sqlmap/1.7.8"')

# Normal traffic
for i in range(15):
    lines.append(f'203.0.113.{i+1} - - [{syslog_ts(200+i*5)}] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"')

Path(OUT / "test_web_attack.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_web_attack.log         {len(lines):>4} lines  | expect: R008 Web Fuzzing + R024 SQL Injection")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Windows Attack — NDJSON (one JSON event per line)
#    R003: privilege escalation, R004: lateral movement, R007: new admin account
# ─────────────────────────────────────────────────────────────────────────────
events = []
# 4625 failures first (account lockout brute)
for i in range(12):
    events.append({"TimeCreated": ts(i*2), "EventID": 4625,
        "SubjectUserName": "jsmith", "TargetUserName": "Administrator",
        "IpAddress": ATTACKER, "LogonType": 3,
        "message": f"An account failed to log on. TargetUserName: Administrator IpAddress: {ATTACKER}"})
# New backdoor account created
events.append({"TimeCreated": ts(30), "EventID": 4720,
    "SubjectUserName": "jsmith", "TargetUserName": "hacker_svc",
    "message": "A user account was created. NewAccountName: hacker_svc SubjectUserName: jsmith"})
# Added to Administrators group
events.append({"TimeCreated": ts(32), "EventID": 4732,
    "SubjectUserName": "jsmith", "MemberName": "hacker_svc",
    "GroupName": "Administrators",
    "message": "A member was added to a security-enabled local group. GroupName: Administrators MemberName: hacker_svc"})
# Lateral movement — same user logs into 4 hosts within 60 seconds
for i, host in enumerate(["SRV-HR-01","SRV-FIN-02","SRV-DEV-03","SRV-MGMT-04"]):
    events.append({"TimeCreated": ts(40+i*10), "EventID": 4624,
        "SubjectUserName": "hacker_svc", "IpAddress": ATTACKER,
        "LogonType": 3, "WorkstationName": host,
        "message": f"Successful logon. TargetUserName: hacker_svc WorkstationName: {host} IpAddress: {ATTACKER}"})
# Mimikatz
events.append({"TimeCreated": ts(90), "EventID": 4688,
    "NewProcessName": "C:\\Temp\\mimikatz.exe",
    "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
    "SubjectUserName": "hacker_svc",
    "message": "Process created: mimikatz.exe privilege::debug sekurlsa::logonpasswords"})
# Event log cleared
events.append({"TimeCreated": ts(95), "EventID": 1102,
    "SubjectUserName": "hacker_svc",
    "message": "The audit log was cleared. SubjectUserName: hacker_svc"})
# Normal events
for i in range(8):
    events.append({"TimeCreated": ts(200+i*30), "EventID": 4624,
        "SubjectUserName": f"user{i:02d}", "IpAddress": INTERNAL,
        "LogonType": 2,
        "message": f"Normal interactive logon. TargetUserName: user{i:02d} IpAddress: {INTERNAL}"})

Path(OUT / "test_windows_attack.json").write_text(
    "\n".join(json.dumps(e) for e in events), encoding="utf-8")
print(f"✓ test_windows_attack.json    {len(events):>4} lines  | expect: R003 PrivEsc + R004 Lateral + R007 New Admin")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Data Exfiltration — firewall log format
#    R005: outbound bytes > threshold to external IP
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# 25 large outbound transfers — each >10MB to external attacker IP
for i in range(25):
    mb = random.randint(20, 150)
    lines.append(
        f"{ts(i*10)} FIREWALL ALLOW outbound "
        f"src={VICTIM} dst={ATTACKER} proto=TCP sport={50000+i} dport=443 "
        f"bytes_out={mb*1024*1024} bytes_in=512 duration=120 action=allow app=HTTPS"
    )
# DLP violations
for i in range(8):
    lines.append(
        f"{ts(300+i*15)} DLP BLOCK user=jsmith src={VICTIM} dst={ATTACKER} "
        f"violation=credit_card file=customer_dump_{i:02d}.csv "
        f"bytes={random.randint(5,50)*1024*1024} severity=critical action=block"
    )
# Normal small DNS/NTP traffic
for i in range(15):
    lines.append(
        f"{ts(500+i*5)} FIREWALL ALLOW outbound src=10.0.0.{i+2} dst=8.8.8.8 "
        f"proto=UDP dport=53 bytes_out=64 bytes_in=128 action=allow"
    )

Path(OUT / "test_exfiltration.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_exfiltration.log       {len(lines):>4} lines  | expect: R005 Data Exfiltration")

# ─────────────────────────────────────────────────────────────────────────────
# 5. AWS CloudTrail Attack — NDJSON
#    R020/R030/R037/R038: cloud privilege escalation + CloudTrail disabled
# ─────────────────────────────────────────────────────────────────────────────
events = []
# Console login brute force
for i in range(10):
    events.append({"eventTime": ts(i*3), "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
        "userIdentity": {"type": "IAMUser", "userName": "admin"},
        "errorCode": "Failed authentication",
        "responseElements": {"ConsoleLogin": "Failure"},
        "message": f"ConsoleLogin Failure attempt {i+1} from {ATTACKER}"})
# Successful login after brute
events.append({"eventTime": ts(32), "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "responseElements": {"ConsoleLogin": "Success"},
    "message": f"ConsoleLogin Success from {ATTACKER} after 10 failures"})
# Create backdoor access key (no MFA)
events.append({"eventTime": ts(35), "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey", "sourceIPAddress": ATTACKER,
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "requestParameters": {"userName": "shadow_admin"},
    "message": "CreateAccessKey for shadow_admin — no MFA present"})
# Attach admin policy
events.append({"eventTime": ts(38), "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy", "sourceIPAddress": ATTACKER,
    "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                          "userName": "shadow_admin"},
    "message": "AttachUserPolicy AdministratorAccess to shadow_admin"})
# Disable CloudTrail (cover tracks)
events.append({"eventTime": ts(42), "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging", "sourceIPAddress": ATTACKER,
    "requestParameters": {"name": "prod-trail"},
    "message": "StopLogging — CloudTrail disabled by attacker"})
# S3 mass download (exfil)
for i in range(20):
    events.append({"eventTime": ts(50+i*5), "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject", "sourceIPAddress": ATTACKER,
        "userIdentity": {"type": "IAMUser", "userName": "shadow_admin"},
        "requestParameters": {"bucketName": "prod-customer-pii", "key": f"records_{i:04d}.csv"},
        "message": f"S3 GetObject prod-customer-pii/records_{i:04d}.csv by shadow_admin"})
# Normal ops
for i in range(6):
    events.append({"eventTime": ts(300+i*20), "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances", "sourceIPAddress": INTERNAL,
        "userIdentity": {"type": "IAMUser", "userName": "devops_bot"},
        "message": "Normal DescribeInstances by devops_bot"})

Path(OUT / "test_aws_attack.json").write_text(
    "\n".join(json.dumps(e) for e in events), encoding="utf-8")
print(f"✓ test_aws_attack.json        {len(events):>4} lines  | expect: R030 Cloud Role + R037 No-MFA + R038 CloudTrail")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Port Scan + C2 Beaconing — firewall log (syslog-style)
#    R002: >10 distinct ports in 30s from same IP
#    R021: regular beacon intervals to external IP
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# Port scan — 50 distinct ports, all within 20 seconds
for i, port in enumerate(range(1, 51)):
    lines.append(
        f"{ts(i//3)} FIREWALL DENY inbound src={ATTACKER} dst={VICTIM} "
        f"proto=TCP dport={port} flags=SYN bytes=64 action=deny"
    )
# C2 beaconing — exactly every 60 seconds (classic malware interval)
for i in range(30):
    lines.append(
        f"{ts(100 + i*60)} FIREWALL ALLOW outbound src={VICTIM} dst={ATTACKER} "
        f"proto=TCP dport=4444 bytes_out=256 bytes_in=1024 action=allow"
    )
# DNS tunneling (long TXT subdomains)
for i in range(10):
    subdomain = "".join(random.choices("abcdef0123456789", k=48)) + ".c2-evil.net"
    lines.append(
        f"{ts(200+i*10)} DNS QUERY src={VICTIM} qtype=TXT "
        f"query={subdomain} ttl=0 response=NOERROR"
    )
# Normal traffic
for i in range(10):
    lines.append(
        f"{ts(500+i*10)} FIREWALL ALLOW outbound src=10.0.0.{i+2} dst=1.1.1.1 "
        f"proto=UDP dport=53 bytes_out=100 bytes_in=200 action=allow"
    )

Path(OUT / "test_c2_beacon.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_c2_beacon.log          {len(lines):>4} lines  | expect: R002 Port Scan + R021 C2 Beaconing")

# ─────────────────────────────────────────────────────────────────────────────
# 7. Benign only — should produce 0 alerts (false-positive check)
# ─────────────────────────────────────────────────────────────────────────────
lines = []
for i in range(60):
    lines.append(f"{syslog_ts(i*10)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")
for i in range(40):
    lines.append(f'203.0.113.{i%254+1} - - [{syslog_ts(i*15)}] "GET /api/health HTTP/1.1" 200 42 "-" "HealthChecker/2.0"')
for i in range(20):
    lines.append(f"{ts(i*30)} FIREWALL ALLOW outbound src=10.0.0.10 dst=8.8.8.8 proto=UDP dport=53 bytes_out=80 bytes_in=180 action=allow")

Path(OUT / "test_benign_only.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_benign_only.log        {len(lines):>4} lines  | expect: 0 alerts (FP check)")

# ─────────────────────────────────────────────────────────────────────────────
# 8. Mixed Realistic — syslog format throughout, chronological, all attacks
#    Uses ONLY syslog format so parser handles it cleanly
# ─────────────────────────────────────────────────────────────────────────────
lines = []
t = 0  # running second counter

# -- SSH brute force (0–60s) --
for i in range(60):
    lines.append(f"{syslog_ts(t)} srv-web-01 sshd[1234]: Failed password for invalid user admin from {ATTACKER} port {40000+i} ssh2")
    t += 1
lines.append(f"{syslog_ts(t)} srv-web-01 sshd[1234]: Accepted password for root from {ATTACKER} port 41999 ssh2"); t += 5

# -- New admin account created (65s) --
lines.append(f"{syslog_ts(t)} DC01 Security[4720]: A user account was created. NewAccountName: hacker_svc SubjectUserName: jsmith IpAddress: {ATTACKER}"); t += 5
lines.append(f"{syslog_ts(t)} DC01 Security[4732]: Member added to Administrators. MemberName: hacker_svc GroupName: Administrators SubjectUserName: jsmith"); t += 5

# -- Lateral movement across 4 hosts in 30s (75s) --
for host in ["SRV-HR-01","SRV-FIN-02","SRV-DEV-03","SRV-MGMT-04"]:
    lines.append(f"{syslog_ts(t)} {host} Security[4624]: Successful logon. TargetUserName: hacker_svc IpAddress: {ATTACKER} LogonType: 3"); t += 7

# -- Mimikatz execution (103s) --
lines.append(f"{syslog_ts(t)} DC01 Security[4688]: New process: C:\\Temp\\mimikatz.exe CommandLine: privilege::debug sekurlsa::logonpasswords SubjectUserName: hacker_svc"); t += 5

# -- Web SQL injection (108s) --
for payload in ["' OR 1=1--", "' UNION SELECT username,password FROM users--", "'; DROP TABLE users;--",
                "1' AND sleep(5)--", "' OR 'x'='x"]:
    enc = urllib.parse.quote(payload)
    lines.append(f"{syslog_ts(t)} nginx access: {ATTACKER} GET /login?user={enc} 500 sqlmap/1.7"); t += 2

# -- 25 web 404s (118s) --
for i in range(25):
    paths = ["/.env","/.git/config","/admin","/wp-admin","/phpmyadmin","/config.php"]
    lines.append(f"{syslog_ts(t)} nginx access: {ATTACKER} GET {paths[i%len(paths)]} 404 sqlmap/1.7"); t += 2

# -- Large outbound exfiltration (168s) --
for i in range(15):
    mb = random.randint(30, 100)
    lines.append(f"{syslog_ts(t)} firewall: ALLOW outbound src={VICTIM} dst={ATTACKER} dport=443 bytes_out={mb*1024*1024} bytes_in=512 action=allow"); t += 5

# -- CloudTrail disabled (243s) --
lines.append(f"{syslog_ts(t)} aws-cloudtrail: StopLogging prod-trail sourceIP={ATTACKER} user=shadow_admin message=CloudTrail_disabled"); t += 3
lines.append(f"{syslog_ts(t)} aws-iam: CreateAccessKey userName=shadow_admin sourceIP={ATTACKER} mfa=false message=CreateAccessKey_no_MFA"); t += 3

# -- C2 beacon every 60s (249s–429s) --
for i in range(5):
    lines.append(f"{syslog_ts(t)} firewall: ALLOW outbound src={VICTIM} dst={ATTACKER} dport=4444 bytes_out=256 bytes_in=1024 action=allow"); t += 60

# -- Port scan (549s) --
for port in range(1, 35):
    lines.append(f"{syslog_ts(t)} firewall: DENY inbound src={ATTACKER} dst={VICTIM} dport={port} proto=TCP flags=SYN action=deny"); t += 1

# -- Normal background noise interspersed at the end --
for i in range(20):
    lines.append(f"{syslog_ts(t+i*5)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")

Path(OUT / "test_mixed_realistic.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_mixed_realistic.log    {len(lines):>4} lines  | expect: ALL alerts (SSH+Web+PrivEsc+Lateral+Exfil+C2+Scan)")

# ─────────────────────────────────────────────────────────────────────────────
print()
print("━"*65)
print(f"  8 test files ready in: {OUT}")
print("━"*65)
print("""
  FILE                        LINES  EXPECTED ALERTS
  ──────────────────────────  ─────  ────────────────────────────────────────
  test_ssh_bruteforce.log      71    R001 Brute Force (CRITICAL)
  test_web_attack.log          85    R008 404 Fuzzing + R024 SQL Injection
  test_windows_attack.json     29    R003 PrivEsc + R004 Lateral + R007 New Admin
  test_exfiltration.log        48    R005 Data Exfiltration (CRITICAL)
  test_aws_attack.json         40    R030 + R037 No-MFA + R038 CloudTrail Disabled
  test_c2_beacon.log          100    R002 Port Scan + R021 C2 Beaconing
  test_benign_only.log        120    ✅ 0 alerts (false-positive check)
  test_mixed_realistic.log    200+   ALL of the above combined
""")
