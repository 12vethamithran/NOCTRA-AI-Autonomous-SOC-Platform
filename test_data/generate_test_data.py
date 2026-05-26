"""
Generate NOCTRA test data — v3 (parser-verified formats).

Every log format verified against engine/parser.py to ensure:
  - timestamp is parsed (not NaT)
  - source_ip / dest_ip extracted
  - bytes extracted (use bytes=, not bytes_out=)
  - status extracted (FAILED / SUCCESS / 404 etc.)
  - event_type extracted (login / http_get / etc.)
"""
import json, random, urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent
random.seed(42)

BASE_TS = datetime(2026, 5, 26, 2, 0, 0, tzinfo=timezone.utc)  # 02:00 UTC off-hours

def ts_iso(sec=0):
    t = BASE_TS + timedelta(seconds=sec)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def ts_apache(sec=0):
    """Standard Apache CLF timestamp — parser handles this correctly."""
    t = BASE_TS + timedelta(seconds=sec)
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

def ts_syslog(sec=0):
    t = BASE_TS + timedelta(seconds=sec)
    return t.strftime("%b %d %H:%M:%S")

ATTACKER = "185.220.101.47"
VICTIM   = "10.0.1.45"
INTERNAL = "10.0.0.5"

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSH Brute Force — syslog format (verified: works)
#    R001: >=3 failed logins from same IP in 60s window
# ─────────────────────────────────────────────────────────────────────────────
lines = []
for i in range(60):  # 60 failures within 59 seconds = dense cluster
    lines.append(f"{ts_syslog(i)} srv-web-01 sshd[1234]: Failed password for invalid user admin from {ATTACKER} port {40000+i} ssh2")
lines.append(f"{ts_syslog(60)} srv-web-01 sshd[1234]: Accepted password for root from {ATTACKER} port 41337 ssh2")
for i in range(10):
    lines.append(f"{ts_syslog(120+i*10)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")

Path(OUT / "test_ssh_bruteforce.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_ssh_bruteforce.log     {len(lines):>4} lines  | R001 Brute Force")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Web Attack — Standard Apache CLF format (timestamp parses correctly)
#    R008: >20 HTTP 404s in 5-minute window
#    R024: SQL injection patterns in raw
#    R025: sqlmap user-agent
# ─────────────────────────────────────────────────────────────────────────────
lines = []
fuzz_paths = ["/.env","/.git/config","/admin","/wp-admin","/phpmyadmin",
              "/config.php","/backup.zip","/.htaccess","/server-status",
              "/actuator/env","/api/debug","/shell.php","/cmd.php"]
# 30 404s within 60 seconds (well within 5-minute window for R008)
for i in range(30):
    path = fuzz_paths[i % len(fuzz_paths)]
    lines.append(f'{ATTACKER} - - [{ts_apache(i*2)}] "GET {path} HTTP/1.1" 404 162 "-" "sqlmap/1.7.8"')

# SQL injection
sqli_payloads = [
    "' OR 1=1--", "' UNION SELECT null,username,password FROM users--",
    "'; DROP TABLE users;--", "1' AND sleep(5)--",
    "' OR 'x'='x", "1; EXEC xp_cmdshell('whoami')--",
    "admin'--", "' UNION SELECT 1,2,3--",
    "union select version(),user(),3--",
    "1 AND 1=1 UNION ALL SELECT NULL--",
]
for i, payload in enumerate(sqli_payloads * 4):
    enc = urllib.parse.quote(payload)
    lines.append(f'{ATTACKER} - - [{ts_apache(61+i*3)}] "GET /login?user={enc}&pass=x HTTP/1.1" 500 0 "-" "sqlmap/1.7.8"')

# Normal traffic
for i in range(15):
    lines.append(f'203.0.113.{i+1} - - [{ts_apache(200+i*5)}] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"')

Path(OUT / "test_web_attack.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_web_attack.log         {len(lines):>4} lines  | R008 Fuzzing + R024 SQLi + R025 Web Shell")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Windows Attack — NDJSON (one JSON object per line)
#    R013: mimikatz / LSASS dumping (raw string match)
#    R018: event log cleared (raw string match)
#    R007: new admin account (event_type + raw match)
# ─────────────────────────────────────────────────────────────────────────────
events = []
# Failed logins (4625)
for i in range(12):
    events.append({"timestamp": ts_iso(i*2), "EventID": 4625,
        "SubjectUserName": "jsmith", "TargetUserName": "Administrator",
        "IpAddress": ATTACKER, "LogonType": 3, "status": "FAILED",
        "event_type": "login",
        "message": f"An account failed to log on. TargetUserName: Administrator IpAddress: {ATTACKER}"})

# New admin account (4720)
events.append({"timestamp": ts_iso(30), "EventID": 4720,
    "SubjectUserName": "jsmith", "TargetUserName": "hacker_svc",
    "IpAddress": ATTACKER, "event_type": "create_user",
    "message": "A user account was created. NewAccountName: hacker_svc SubjectUserName: jsmith"})

# Added to Administrators (4732)
events.append({"timestamp": ts_iso(32), "EventID": 4732,
    "SubjectUserName": "jsmith", "MemberName": "hacker_svc",
    "GroupName": "Administrators", "event_type": "4732",
    "message": "Member added to Administrators group. MemberName: hacker_svc GroupName: Administrators"})

# Lateral movement — 4 hosts in <5min
for i, host in enumerate(["SRV-HR-01","SRV-FIN-02","SRV-DEV-03","SRV-MGMT-04"]):
    events.append({"timestamp": ts_iso(40+i*10), "EventID": 4624,
        "SubjectUserName": "hacker_svc", "IpAddress": ATTACKER,
        "WorkstationName": host, "LogonType": 3, "status": "SUCCESS",
        "event_type": "logon",
        "message": f"Successful logon. TargetUserName: hacker_svc WorkstationName: {host} IpAddress: {ATTACKER}"})

# Mimikatz / LSASS dump (R013 fires on raw string match)
events.append({"timestamp": ts_iso(90), "EventID": 4688,
    "NewProcessName": "C:\\Temp\\mimikatz.exe",
    "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
    "SubjectUserName": "hacker_svc", "IpAddress": ATTACKER,
    "event_type": "process_create",
    "message": "Process created: mimikatz.exe privilege::debug sekurlsa::logonpasswords SubjectUserName: hacker_svc"})

# Event log cleared (R018 fires on raw string match)
events.append({"timestamp": ts_iso(95), "EventID": 1102,
    "SubjectUserName": "hacker_svc",
    "event_type": "audit",
    "message": "The audit log was cleared. SubjectUserName: hacker_svc eventid: 1102"})

# Normal logins
for i in range(8):
    events.append({"timestamp": ts_iso(200+i*30), "EventID": 4624,
        "SubjectUserName": f"user{i:02d}", "IpAddress": INTERNAL,
        "LogonType": 2, "status": "SUCCESS", "event_type": "logon",
        "message": f"Normal interactive logon. TargetUserName: user{i:02d} IpAddress: {INTERNAL}"})

Path(OUT / "test_windows_attack.json").write_text(
    "\n".join(json.dumps(e) for e in events), encoding="utf-8")
print(f"✓ test_windows_attack.json    {len(events):>4} lines  | R007 + R013 LSASS + R018 Log Cleared")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Data Exfiltration — logfmt with time= and bytes= (verified: parser reads these)
#    R005: outbound bytes > threshold to external IP
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# Large outbound transfers — use bytes= (not bytes_out=) so parser picks it up
for i in range(25):
    mb = random.randint(20, 150)
    lines.append(
        f"time={ts_iso(i*10)} action=allow direction=outbound "
        f"src={VICTIM} dst={ATTACKER} proto=TCP sport={50000+i} dport=443 "
        f"bytes={mb*1024*1024} duration=120 app=HTTPS"
    )
# DLP violations (raw match for R024/R027 as bonus)
for i in range(8):
    mb = random.randint(5, 50)
    lines.append(
        f"time={ts_iso(300+i*15)} action=block direction=outbound "
        f"src={VICTIM} dst={ATTACKER} user=jsmith "
        f"bytes={mb*1024*1024} violation=credit_card file=customer_dump_{i:02d}.csv severity=critical"
    )
# Normal small traffic
for i in range(15):
    lines.append(
        f"time={ts_iso(500+i*5)} action=allow direction=outbound "
        f"src=10.0.0.{i+2} dst=8.8.8.8 proto=UDP dport=53 bytes=64"
    )

Path(OUT / "test_exfiltration.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_exfiltration.log       {len(lines):>4} lines  | R005 Data Exfiltration")

# ─────────────────────────────────────────────────────────────────────────────
# 5. AWS CloudTrail — NDJSON with explicit field names
#    R013/R018 raw-match based rules + ML
# ─────────────────────────────────────────────────────────────────────────────
events = []
for i in range(10):
    events.append({"timestamp": ts_iso(i*3), "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
        "source_ip": ATTACKER,
        "userIdentity": {"type": "IAMUser", "userName": "admin"},
        "errorCode": "Failed authentication",
        "responseElements": {"ConsoleLogin": "Failure"},
        "status": "FAILED", "event_type": "login",
        "message": f"ConsoleLogin Failure attempt {i+1} from {ATTACKER} errorCode: Failed authentication"})

events.append({"timestamp": ts_iso(32), "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin", "sourceIPAddress": ATTACKER,
    "source_ip": ATTACKER, "status": "SUCCESS", "event_type": "login",
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "responseElements": {"ConsoleLogin": "Success"},
    "message": f"ConsoleLogin Success from {ATTACKER} after repeated failures"})

events.append({"timestamp": ts_iso(35), "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey", "sourceIPAddress": ATTACKER,
    "source_ip": ATTACKER, "event_type": "attachuserpolicy",
    "userIdentity": {"type": "IAMUser", "userName": "admin"},
    "requestParameters": {"userName": "shadow_admin"},
    "message": "CreateAccessKey for shadow_admin without MFA — AdministratorAccess policy attached"})

events.append({"timestamp": ts_iso(38), "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy", "sourceIPAddress": ATTACKER,
    "source_ip": ATTACKER, "event_type": "attachuserpolicy",
    "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "shadow_admin"},
    "message": "AttachUserPolicy AdministratorAccess to shadow_admin — privileged role administrator granted"})

# CloudTrail disabled (R018 raw match)
events.append({"timestamp": ts_iso(42), "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging", "sourceIPAddress": ATTACKER,
    "source_ip": ATTACKER, "event_type": "audit",
    "requestParameters": {"name": "prod-trail"},
    "message": "StopLogging prod-trail — audit log was cleared by shadow_admin eventid: 1102"})

# S3 mass download
for i in range(20):
    events.append({"timestamp": ts_iso(50+i*5), "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject", "sourceIPAddress": ATTACKER,
        "source_ip": ATTACKER,
        "userIdentity": {"type": "IAMUser", "userName": "shadow_admin"},
        "requestParameters": {"bucketName": "prod-customer-pii", "key": f"records_{i:04d}.csv"},
        "message": f"S3 GetObject prod-customer-pii/records_{i:04d}.csv by shadow_admin"})

# Normal ops
for i in range(5):
    events.append({"timestamp": ts_iso(300+i*20), "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances", "sourceIPAddress": INTERNAL,
        "source_ip": INTERNAL,
        "userIdentity": {"type": "IAMUser", "userName": "devops_bot"},
        "message": "Normal DescribeInstances by devops_bot"})

Path(OUT / "test_aws_attack.json").write_text(
    "\n".join(json.dumps(e) for e in events), encoding="utf-8")
print(f"✓ test_aws_attack.json        {len(events):>4} lines  | R018 CloudTrail + R030 Cloud Admin + ML")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Port Scan + C2 Beaconing — logfmt with time= key (timestamp parses correctly)
#    R002: >10 distinct ports in 30s
#    R021: regular beacon interval to external dest
# ─────────────────────────────────────────────────────────────────────────────
lines = []
# Port scan — 50 ports in 16 seconds (time= so timestamp is parsed)
for i, port in enumerate(range(1, 51)):
    lines.append(
        f"time={ts_iso(i//3)} action=deny direction=inbound "
        f"src={ATTACKER} dst={VICTIM} proto=TCP dport={port} flags=SYN bytes=64"
    )

# C2 beaconing — EXACTLY 60s intervals, 20 connections (R021 needs 6+ and CV<0.30)
for i in range(20):
    lines.append(
        f"time={ts_iso(100+i*60)} action=allow direction=outbound "
        f"src={VICTIM} dst={ATTACKER} proto=TCP dport=4444 bytes=256"
    )

# DNS tunneling — long subdomains (R028 suspicious domain contact)
for i in range(10):
    subdomain = "".join(random.choices("abcdef0123456789", k=32)) + ".evil-c2.xyz"
    lines.append(
        f"time={ts_iso(200+i*10)} action=allow event_type=dns "
        f"src={VICTIM} dst=8.8.8.8 query={subdomain} qtype=TXT"
    )

# Normal traffic
for i in range(10):
    lines.append(
        f"time={ts_iso(500+i*10)} action=allow direction=outbound "
        f"src=10.0.0.{i+2} dst=1.1.1.1 proto=UDP dport=53 bytes=100"
    )

Path(OUT / "test_c2_beacon.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_c2_beacon.log          {len(lines):>4} lines  | R002 Port Scan + R021 C2 Beaconing")

# ─────────────────────────────────────────────────────────────────────────────
# 7. Benign only — 0 alerts expected
# ─────────────────────────────────────────────────────────────────────────────
lines = []
for i in range(60):
    lines.append(f"{ts_syslog(i*10)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")
for i in range(40):
    lines.append(f'203.0.113.{i%254+1} - - [{ts_apache(i*15)}] "GET /api/health HTTP/1.1" 200 42 "-" "HealthChecker/2.0"')
for i in range(20):
    lines.append(f"time={ts_iso(i*30)} action=allow src=10.0.0.10 dst=8.8.8.8 proto=UDP dport=53 bytes=80")

Path(OUT / "test_benign_only.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_benign_only.log        {len(lines):>4} lines  | 0 alerts expected")

# ─────────────────────────────────────────────────────────────────────────────
# 8. Mixed Realistic — syslog format, chronological, all attack types
#    Uses verified syslog format throughout for clean parsing
# ─────────────────────────────────────────────────────────────────────────────
lines = []
t = 0

# SSH brute force (R001)
for i in range(60):
    lines.append(f"{ts_syslog(t)} srv-web-01 sshd[1234]: Failed password for invalid user admin from {ATTACKER} port {40000+i} ssh2")
    t += 1
lines.append(f"{ts_syslog(t)} srv-web-01 sshd[1234]: Accepted password for root from {ATTACKER} port 41999 ssh2"); t += 5

# Mimikatz / LSASS (R013)
lines.append(f"{ts_syslog(t)} DC01 sshd[4688]: Process created: mimikatz.exe privilege::debug sekurlsa::logonpasswords SubjectUserName hacker_svc"); t += 3

# Event log cleared (R018)
lines.append(f"{ts_syslog(t)} DC01 sshd[1102]: The audit log was cleared. SubjectUserName hacker_svc eventid: 1102"); t += 3

# New admin account (R007) — create_user event_type with admin in raw
lines.append(f"{ts_syslog(t)} DC01 sshd[4720]: A user account was created. NewAccountName hacker_svc SubjectUserName jsmith Administrators group added"); t += 3

# SQL Injection (R024) — raw string match
for payload in ["' OR 1=1--", "' UNION SELECT username,password FROM users--",
                "'; DROP TABLE users;--", "union select version(),user(),3--",
                "1' AND sleep(5)--", "xp_cmdshell whoami"]:
    enc = urllib.parse.quote(payload)
    lines.append(f"{ts_syslog(t)} nginx sshd[200]: GET /login?user={enc} 500 {ATTACKER} sqlmap/1.7"); t += 2

# C2 Beacon (R021) — need logfmt with time= but we're in syslog, so encode
# Use raw-matching rule instead: R028 suspicious domain contact via xyz TLD
for i in range(12):
    subdomain = "".join(random.choices("abcdef0123456789", k=32))
    lines.append(f"{ts_syslog(t)} {VICTIM} named[53]: query {subdomain}.c2beacon.xyz TXT NOERROR {ATTACKER}"); t += 2

# Cleartext credentials (R015)
for i in range(5):
    lines.append(f"{ts_syslog(t)} webapp sshd[443]: POST /api/login password=letmein123 api_key=sk-abc123 src={ATTACKER}"); t += 2

# Normal noise
for i in range(20):
    lines.append(f"{ts_syslog(t+i*5)} srv-web-01 sshd[999]: Accepted publickey for deploy from {INTERNAL} port {55000+i} ssh2")

Path(OUT / "test_mixed_realistic.log").write_text("\n".join(lines), encoding="utf-8")
print(f"✓ test_mixed_realistic.log    {len(lines):>4} lines  | R001+R013+R018+R024+R015+ML")

# ─────────────────────────────────────────────────────────────────────────────
# Verify all files by running actual rules
# ─────────────────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from engine.parser import parse
from engine.rules import run_all_rules

print()
print("━"*65)
print("  VERIFICATION — running rules on each file")
print("━"*65)
total_alerts = 0
for fname in ["test_ssh_bruteforce.log","test_web_attack.log","test_windows_attack.json",
              "test_exfiltration.log","test_aws_attack.json","test_c2_beacon.log",
              "test_benign_only.log","test_mixed_realistic.log"]:
    content = (OUT / fname).read_bytes()
    result = parse(fname, content)
    alerts = run_all_rules(result.dataframe)
    total_alerts += len(alerts)
    status = "✅" if (fname == "test_benign_only.log" and len(alerts)==0) else ("🔴" if alerts else "⚠️ ")
    print(f"  {status} {fname:<35} {len(alerts):>2} alert(s): {', '.join(a.rule_id for a in alerts) or 'none'}")

print(f"\n  Total alerts across all files: {total_alerts}")
