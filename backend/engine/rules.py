"""
engine/rules.py
===============
The ten detection rules that scan the in-RAM DataFrame.

Each rule is a pure function: `(df: pd.DataFrame) -> list[Alert]`.
No side effects, no global state. They are easy to unit-test and easy to
swap out / extend without touching the pipeline.

The whole detection pass lives in `run_all_rules(df)` which the /ingest
router calls right after parsing.

Rule list (matches MySOC_Notes.md):
    R001 Brute Force                — >5 failed logins from same IP in 60s
    R002 Port Scan                  — >10 distinct ports from same IP in 30s
    R003 Privilege Escalation       — normal user becomes admin
    R004 Lateral Movement           — same user authenticates on 3+ hosts in 5m
    R005 Data Exfiltration          — outbound bytes > threshold to external IP
    R006 Suspicious Login Time      — auth between 00:00-05:00 for non-service acct
    R007 New Admin Account          — new user created with admin privileges
    R008 Repeated 404s              — >20 HTTP 404s from same IP (web fuzzing)
    R009 Known Malicious IP         — flagged later by threat intel enrichment
    R010 Multi-Service Attack       — failures across SSH + HTTP + FTP from one IP
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import timedelta
from typing import Callable, List

import pandas as pd

from schemas.alert import Alert, AlertSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _new_alert_id() -> str:
    """Short, unique alert ID for this session."""
    return uuid.uuid4().hex[:12]


def _is_external_ip(ip: str | None) -> bool:
    """True if the IP is public (not RFC1918 / loopback / link-local)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def _safe_ts(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows where timestamp didn't parse — most rules need a real time."""
    if "timestamp" not in df.columns:
        return df.iloc[0:0]
    return df[df["timestamp"].notna()].copy()


# ---------------------------------------------------------------------------
# R001 — Brute Force
# ---------------------------------------------------------------------------
def rule_r001_brute_force(df: pd.DataFrame) -> List[Alert]:
    """
    >5 FAILED login events from the same source_ip within any 60-second window.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty:
        return alerts

    failed = work[
        (work["event_type"].astype(str).str.lower().str.contains("login|auth|logon", na=False))
        & (work["status"].astype(str).str.upper() == "FAILED")
        & (work["source_ip"].notna())
    ].copy()
    if failed.empty:
        return alerts

    failed = failed.sort_values("timestamp")
    for src_ip, group in failed.groupby("source_ip"):
        # Sliding 60-second window — for each row, count how many failures
        # happened within the last 60s from the same IP.
        times = group["timestamp"]
        window = timedelta(seconds=60)
        # Vectorised: searchsorted from each timestamp - 60s
        starts = times - window
        # `searchsorted` on a sorted Series gives us indices.
        idx_arr = times.values
        counts = []
        for t in times:
            counts.append(((times >= (t - window)) & (times <= t)).sum())
        group = group.assign(_window_count=counts)
        spike = group[group["_window_count"] > 5]
        if spike.empty:
            continue
        # Build a single alert per IP keyed on the worst window.
        worst = spike.iloc[spike["_window_count"].argmax()]
        # All FAILED rows within the worst 60s window — these are what the
        # analyst needs to see, not just the row that crossed the threshold.
        peak_window_failures = group[
            (group["timestamp"] >= worst["timestamp"] - window)
            & (group["timestamp"] <= worst["timestamp"])
        ]
        users = sorted({str(u) for u in peak_window_failures["user"].dropna().tolist()})
        # Did the attacker eventually succeed?
        success = work[
            (work["source_ip"] == src_ip)
            & (work["status"].astype(str).str.upper() == "SUCCESS")
            & (work["timestamp"] >= group["timestamp"].min())
            & (work["timestamp"] <= group["timestamp"].max() + timedelta(minutes=2))
        ]
        succeeded = not success.empty

        related_idx = list(peak_window_failures.index) + list(success.index)
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R001",
                rule_name="Brute Force Attack",
                severity=AlertSeverity.CRITICAL if succeeded else AlertSeverity.HIGH,
                description=(
                    f"{int(worst['_window_count'])} failed logins from {src_ip} "
                    f"in a 60-second window"
                    + (f" — credential compromise: SUCCEEDED for user(s) "
                       f"{', '.join(success['user'].dropna().unique())}" if succeeded else "")
                ),
                timestamp=worst["timestamp"].to_pydatetime(),
                source_ip=src_ip,
                user=", ".join(users) if users else None,
                event_count=len(related_idx),
                mitre_technique="T1110",
                mitre_tactic="Credential Access",
                related_log_indices=related_idx,
                extra={
                    "users_targeted": users,
                    "credential_compromise": succeeded,
                    "peak_window_failures": int(worst["_window_count"]),
                },
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R002 — Port Scan
# ---------------------------------------------------------------------------
def rule_r002_port_scan(df: pd.DataFrame) -> List[Alert]:
    """
    >10 distinct destination ports hit from the same source_ip within 30 seconds.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty or "port" not in work.columns:
        return alerts
    work = work[work["source_ip"].notna() & work["port"].notna()].copy()
    if work.empty:
        return alerts

    work = work.sort_values("timestamp")
    window = timedelta(seconds=30)
    for src_ip, group in work.groupby("source_ip"):
        if group["port"].nunique() < 10:
            continue  # cheap pre-filter
        # Sliding window: count distinct ports in each 30s window.
        peak_distinct = 0
        peak_rows: List[int] = []
        for t in group["timestamp"]:
            window_rows = group[(group["timestamp"] >= t - window) & (group["timestamp"] <= t)]
            distinct = window_rows["port"].nunique()
            if distinct > peak_distinct:
                peak_distinct = distinct
                peak_rows = list(window_rows.index)
        if peak_distinct <= 10:
            continue
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R002",
                rule_name="Port Scan",
                severity=AlertSeverity.HIGH,
                description=f"{peak_distinct} distinct ports probed by {src_ip} in 30s",
                timestamp=group.loc[peak_rows[0], "timestamp"].to_pydatetime(),
                source_ip=src_ip,
                event_count=len(peak_rows),
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                related_log_indices=peak_rows,
                extra={"distinct_ports": peak_distinct},
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R003 — Privilege Escalation
# ---------------------------------------------------------------------------
_ADMIN_USERS = {"root", "admin", "administrator", "sudo"}


def rule_r003_priv_esc(df: pd.DataFrame) -> List[Alert]:
    """
    A normal user has a successful auth event and then, shortly after, an
    admin-level event from the same host. Heuristic: same source_ip, normal
    user SUCCESS → admin user SUCCESS within 10 minutes.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty:
        return alerts
    auths = work[
        (work["event_type"].astype(str).str.lower().str.contains("login|auth|logon|sudo|su", na=False))
        & (work["status"].astype(str).str.upper() == "SUCCESS")
        & (work["user"].notna())
        & (work["source_ip"].notna())
    ].copy()
    if auths.empty:
        return alerts
    auths = auths.sort_values("timestamp")
    for src_ip, group in auths.groupby("source_ip"):
        normals = group[~group["user"].astype(str).str.lower().isin(_ADMIN_USERS)]
        admins = group[group["user"].astype(str).str.lower().isin(_ADMIN_USERS)]
        if normals.empty or admins.empty:
            continue
        # Did an admin auth happen within 10 minutes after a normal one?
        for _, n in normals.iterrows():
            window = admins[(admins["timestamp"] > n["timestamp"])
                            & (admins["timestamp"] <= n["timestamp"] + timedelta(minutes=10))]
            if window.empty:
                continue
            a = window.iloc[0]
            alerts.append(
                Alert(
                    alert_id=_new_alert_id(),
                    rule_id="R003",
                    rule_name="Privilege Escalation",
                    severity=AlertSeverity.CRITICAL,
                    description=(
                        f"User {n['user']} on {src_ip} escalated to {a['user']} "
                        f"within {int((a['timestamp']-n['timestamp']).total_seconds())}s"
                    ),
                    timestamp=a["timestamp"].to_pydatetime(),
                    source_ip=src_ip,
                    user=f"{n['user']} -> {a['user']}",
                    event_count=2,
                    mitre_technique="T1078",
                    mitre_tactic="Privilege Escalation",
                    related_log_indices=[int(n.name), int(a.name)],
                )
            )
            break  # one alert per src_ip is enough
    return alerts


# ---------------------------------------------------------------------------
# R004 — Lateral Movement
# ---------------------------------------------------------------------------
def rule_r004_lateral(df: pd.DataFrame) -> List[Alert]:
    """
    Same user authenticates SUCCESS-fully on 3+ different destination hosts
    within a 5-minute window.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty or "dest_ip" not in work.columns:
        return alerts
    auths = work[
        (work["event_type"].astype(str).str.lower().str.contains("login|auth|logon", na=False))
        & (work["status"].astype(str).str.upper() == "SUCCESS")
        & (work["user"].notna())
        & (work["dest_ip"].notna())
    ].copy()
    if auths.empty:
        return alerts
    window = timedelta(minutes=5)
    for user, group in auths.groupby("user"):
        if group["dest_ip"].nunique() < 3:
            continue
        group = group.sort_values("timestamp")
        for _, row in group.iterrows():
            window_rows = group[(group["timestamp"] >= row["timestamp"])
                                & (group["timestamp"] <= row["timestamp"] + window)]
            hosts = window_rows["dest_ip"].nunique()
            if hosts >= 3:
                alerts.append(
                    Alert(
                        alert_id=_new_alert_id(),
                        rule_id="R004",
                        rule_name="Lateral Movement",
                        severity=AlertSeverity.HIGH,
                        description=f"User {user} authed on {hosts} hosts in 5m",
                        timestamp=row["timestamp"].to_pydatetime(),
                        source_ip=row.get("source_ip"),
                        user=str(user),
                        event_count=len(window_rows),
                        mitre_technique="T1021",
                        mitre_tactic="Lateral Movement",
                        related_log_indices=list(window_rows.index),
                        extra={"hosts_visited": sorted(window_rows["dest_ip"].dropna().unique().tolist())},
                    )
                )
                break  # one per user
    return alerts


# ---------------------------------------------------------------------------
# R005 — Data Exfiltration
# ---------------------------------------------------------------------------
def rule_r005_exfil(df: pd.DataFrame) -> List[Alert]:
    """
    A single outbound transfer > 100 MB to an external destination IP.
    """
    alerts: List[Alert] = []
    if "bytes" not in df.columns or "dest_ip" not in df.columns:
        return alerts
    work = df[df["bytes"].notna() & df["dest_ip"].notna()].copy()
    if work.empty:
        return alerts
    threshold = 100 * 1024 * 1024  # 100 MB
    big = work[work["bytes"].astype("Int64").fillna(0).astype(int) > threshold]
    big = big[big["dest_ip"].apply(_is_external_ip)]
    for idx, row in big.iterrows():
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R005",
                rule_name="Data Exfiltration",
                severity=AlertSeverity.HIGH,
                description=(
                    f"{int(row['bytes'])/1024/1024:.1f} MB transferred to external "
                    f"IP {row['dest_ip']}"
                ),
                timestamp=row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None,
                source_ip=row.get("source_ip"),
                dest_ip=row.get("dest_ip"),
                user=row.get("user"),
                event_count=1,
                mitre_technique="T1041",
                mitre_tactic="Exfiltration",
                related_log_indices=[int(idx)],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R006 — Suspicious Login Time
# ---------------------------------------------------------------------------
_SERVICE_USERS = {"backup", "cron", "service", "system", "_apt"}


def rule_r006_off_hours(df: pd.DataFrame) -> List[Alert]:
    """
    Successful login between 00:00 and 05:00 for a non-service account.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty:
        return alerts
    auths = work[
        (work["event_type"].astype(str).str.lower().str.contains("login|auth|logon", na=False))
        & (work["status"].astype(str).str.upper() == "SUCCESS")
        & (work["user"].notna())
    ].copy()
    if auths.empty:
        return alerts
    auths["hour"] = auths["timestamp"].dt.hour
    odd = auths[
        (auths["hour"].between(0, 5))
        & (~auths["user"].astype(str).str.lower().isin(_SERVICE_USERS))
    ]
    for idx, row in odd.iterrows():
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R006",
                rule_name="Suspicious Login Time",
                severity=AlertSeverity.MEDIUM,
                description=f"{row['user']} logged in at {row['timestamp'].strftime('%H:%M')} UTC",
                timestamp=row["timestamp"].to_pydatetime(),
                source_ip=row.get("source_ip"),
                user=str(row["user"]),
                event_count=1,
                mitre_technique="T1078",
                mitre_tactic="Defense Evasion",
                related_log_indices=[int(idx)],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R007 — New Admin Account Created
# ---------------------------------------------------------------------------
def rule_r007_new_admin(df: pd.DataFrame) -> List[Alert]:
    """
    Event types that look like 'user_created' / 'account_added' targeting a user
    in _ADMIN_USERS or with an 'admin' substring.
    """
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    creations = df[
        df["event_type"].astype(str).str.lower().str.contains(
            "create_user|user_created|account_added|new_user|useradd", na=False
        )
    ]
    if creations.empty:
        return alerts
    creations = creations[
        creations["user"].astype(str).str.lower().isin(_ADMIN_USERS)
        | creations["user"].astype(str).str.lower().str.contains("admin", na=False)
    ]
    for idx, row in creations.iterrows():
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R007",
                rule_name="New Admin Account Created",
                severity=AlertSeverity.HIGH,
                description=f"Admin account '{row['user']}' was created",
                timestamp=row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None,
                source_ip=row.get("source_ip"),
                user=str(row["user"]),
                event_count=1,
                mitre_technique="T1136",
                mitre_tactic="Persistence",
                related_log_indices=[int(idx)],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R008 — Repeated 404s (recon / fuzzing)
# ---------------------------------------------------------------------------
def rule_r008_fuzzing(df: pd.DataFrame) -> List[Alert]:
    """
    >20 HTTP 404 status codes from the same source IP across the file.
    """
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    http = df[
        df["event_type"].astype(str).str.lower().str.startswith("http", na=False)
        | (df["event_type"].astype(str).str.lower() == "http")
    ].copy()
    if http.empty:
        return alerts
    http = http[http["status"].astype(str) == "404"]
    if http.empty:
        return alerts
    by_ip = http.groupby("source_ip")
    for src_ip, group in by_ip:
        if len(group) < 20:
            continue
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R008",
                rule_name="Web Recon / Fuzzing",
                severity=AlertSeverity.MEDIUM,
                description=f"{len(group)} HTTP 404 responses to {src_ip}",
                timestamp=group["timestamp"].min().to_pydatetime() if pd.notna(group["timestamp"].min()) else None,
                source_ip=str(src_ip),
                event_count=len(group),
                mitre_technique="T1595",
                mitre_tactic="Reconnaissance",
                related_log_indices=list(group.index),
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R009 — Known Malicious IP (placeholder)
# ---------------------------------------------------------------------------
def rule_r009_malicious_ip(df: pd.DataFrame) -> List[Alert]:
    """
    Placeholder rule. The actual malicious-IP enrichment runs lazily via the
    /threatintel router when the analyst inspects an alert. We don't burn API
    quota up-front on every IP. This stub stays here so the rule numbering
    matches the spec and tests can reference R009.
    """
    return []


# ---------------------------------------------------------------------------
# R010 — Multi-Service Attack
# ---------------------------------------------------------------------------
def rule_r010_multi_service(df: pd.DataFrame) -> List[Alert]:
    """
    Same source IP causes FAILED events across 3+ distinct services
    (e.g. ssh + http + ftp + login).
    """
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    bad = df[
        df["status"].astype(str).str.upper().isin(["FAILED", "401", "403", "404"])
        & df["source_ip"].notna()
        & df["event_type"].notna()
    ]
    if bad.empty:
        return alerts
    by_ip = bad.groupby("source_ip")
    for src_ip, group in by_ip:
        services = {
            s.lower() for s in group["event_type"].astype(str).unique()
            if s and s.lower() != "nan"
        }
        # Normalise http_get/http_post -> http for the distinct-service count.
        norm = {s.split("_")[0] for s in services}
        if len(norm) < 3:
            continue
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R010",
                rule_name="Multi-Service Attack",
                severity=AlertSeverity.HIGH,
                description=(
                    f"{src_ip} attacked {len(norm)} different services: "
                    f"{', '.join(sorted(norm))}"
                ),
                timestamp=group["timestamp"].min().to_pydatetime()
                    if pd.notna(group["timestamp"].min()) else None,
                source_ip=str(src_ip),
                event_count=len(group),
                mitre_technique="T1110.003",
                mitre_tactic="Credential Access",
                related_log_indices=list(group.index),
                extra={"services": sorted(norm)},
            )
        )
    return alerts


# ===========================================================================
# Expanded rule pack — R011-R025
# Higher-fidelity signatures across the MITRE kill-chain. Each rule sets a
# pre-populated tp_probability when the signal is unambiguous so confirmed
# patterns surface above 90% confidence even before AI re-scoring.
# ===========================================================================
def _raw_contains(df: pd.DataFrame, patterns: list[str]) -> pd.DataFrame:
    """Return rows whose `raw` field contains any of the case-insensitive patterns."""
    if "raw" not in df.columns or df.empty:
        return df.iloc[0:0]
    haystack = df["raw"].astype(str).str.lower()
    mask = pd.Series(False, index=df.index)
    for p in patterns:
        mask = mask | haystack.str.contains(p.lower(), na=False, regex=False)
    return df[mask].copy()


def _safe_min_ts(group: pd.DataFrame):
    if "timestamp" not in group.columns or group["timestamp"].dropna().empty:
        return None
    v = group["timestamp"].min()
    return v.to_pydatetime() if pd.notna(v) else None


# ---------------------------------------------------------------------------
# R011 — Suspicious PowerShell Execution (T1059.001 / Execution)
# ---------------------------------------------------------------------------
def rule_r011_powershell(df: pd.DataFrame) -> List[Alert]:
    """
    Process / command-line events that include PowerShell with encoded payloads,
    download cradles, or AMSI bypass markers.
    """
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "powershell -enc", "powershell.exe -encoded", "-encodedcommand",
        "iex (new-object net.webclient).downloadstring",
        "amsiscanbuffer", "amsi.dll", "frombase64string",
        "downloadstring(", "invoke-expression",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R011",
            rule_name="Suspicious PowerShell Execution",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} PowerShell event(s) with encoded or download-cradle patterns from {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            user=str(grp["user"].dropna().iloc[0]) if grp["user"].dropna().size else None,
            event_count=len(grp),
            mitre_technique="T1059.001",
            mitre_tactic="Execution",
            tp_probability=0.92,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R012 — Process Injection markers (T1055 / Defense Evasion)
# ---------------------------------------------------------------------------
def rule_r012_process_injection(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "createremotethread", "writeprocessmemory", "ntmapviewofsection",
        "queueuserapc", "setwindowshookex", "reflective dll",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R012",
            rule_name="Process Injection Indicators",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} process-injection API call(s) observed from {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1055",
            mitre_tactic="Defense Evasion",
            tp_probability=0.90,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R013 — LSASS Memory Access (T1003.001 / Credential Access)
# ---------------------------------------------------------------------------
def rule_r013_lsass(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "lsass.exe", "lsass.dmp", "minidumpwritedump",
        "procdump -ma lsass", "comsvcs.dll, minidump",
        "sekurlsa::logonpasswords", "mimikatz",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R013",
            rule_name="LSASS / Credential Dumping",
            severity=AlertSeverity.CRITICAL,
            description=f"{len(grp)} LSASS access or credential-dumping pattern(s) on {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1003.001",
            mitre_tactic="Credential Access",
            tp_probability=0.96,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R014 — DNS Tunneling (T1071.004 / Command & Control)
# Long DNS queries or high-volume to a single domain
# ---------------------------------------------------------------------------
def rule_r014_dns_tunnel(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    dns = df[df["event_type"].astype(str).str.lower().str.contains("dns", na=False)].copy()
    if dns.empty:
        return alerts
    # Indicator: > 50 DNS queries from one source AND avg label length > 30
    by_src = dns.groupby(dns["source_ip"].fillna("local"))
    for src, grp in by_src:
        if len(grp) < 50:
            continue
        raw_avg_len = grp["raw"].astype(str).str.len().mean() if "raw" in grp.columns else 0
        if raw_avg_len < 60:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R014",
            rule_name="DNS Tunneling Suspected",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} unusually long DNS queries from {src} (avg payload {int(raw_avg_len)} chars)",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1071.004",
            mitre_tactic="Command and Control",
            tp_probability=0.88,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R015 — Cleartext Credentials in URL/Logs (T1552.001 / Credential Access)
# ---------------------------------------------------------------------------
def rule_r015_cleartext_creds(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "password=", "passwd=", "pwd=", "api_key=", "apikey=",
        "secret=", "token=", "authorization: basic ",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R015",
            rule_name="Cleartext Credentials in Traffic",
            severity=AlertSeverity.MEDIUM,
            description=f"{len(grp)} log line(s) containing exposed credential material from {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1552.001",
            mitre_tactic="Credential Access",
            tp_probability=0.78,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R016 — Account Lockout Storm (T1110.004 / Credential Access)
# Many distinct user lockouts from few sources within a window
# ---------------------------------------------------------------------------
def rule_r016_lockout_storm(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    locks = df[
        df["raw"].astype(str).str.lower().str.contains("lockout|account locked|locked out", na=False, regex=True)
    ].copy() if "raw" in df.columns else df.iloc[0:0]
    if locks.empty:
        return alerts
    by_src = locks.groupby(locks["source_ip"].fillna("unknown"))
    for src, grp in by_src:
        users = grp["user"].dropna().unique()
        if len(users) < 5:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R016",
            rule_name="Account Lockout Storm",
            severity=AlertSeverity.HIGH,
            description=f"{len(users)} distinct accounts locked out from {src}",
            timestamp=ts,
            source_ip=None if src == "unknown" else str(src),
            event_count=len(grp),
            mitre_technique="T1110.004",
            mitre_tactic="Credential Access",
            tp_probability=0.91,
            related_log_indices=list(grp.index),
            extra={"locked_users": list(users)[:10]},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R017 — New Service / Scheduled Task Persistence (T1543 / T1053)
# ---------------------------------------------------------------------------
def rule_r017_persistence(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "sc.exe create", "new-service", "schtasks /create", "at \\\\",
        "crontab -e", "/etc/cron.d/", "systemctl enable",
        "registry run key", "hklm\\software\\microsoft\\windows\\currentversion\\run",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R017",
            rule_name="Suspicious Persistence Mechanism",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} service / scheduled-task / cron / run-key creation event(s) on {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1543.003",
            mitre_tactic="Persistence",
            tp_probability=0.85,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R018 — Event Log Cleared (T1070.001 / Defense Evasion)
# Extremely high-fidelity: clearing logs is almost never benign in prod.
# ---------------------------------------------------------------------------
def rule_r018_log_cleared(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "eventid: 1102", "eventid:1102", "event log was cleared",
        "wevtutil cl ", "clear-eventlog", "audit log was cleared",
    ])
    if hits.empty:
        return alerts
    for _, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R018",
            rule_name="Event Log Cleared",
            severity=AlertSeverity.CRITICAL,
            description="Security/audit event log was cleared — strong evasion indicator",
            timestamp=ts,
            source_ip=str(row["source_ip"]) if pd.notna(row.get("source_ip")) else None,
            user=str(row["user"]) if pd.notna(row.get("user")) else None,
            event_count=1,
            mitre_technique="T1070.001",
            mitre_tactic="Defense Evasion",
            tp_probability=0.98,
            related_log_indices=[int(row.name)],
        ))
    return alerts


# ---------------------------------------------------------------------------
# R019 — Defender / AV Tampering (T1562.001 / Defense Evasion)
# ---------------------------------------------------------------------------
def rule_r019_av_tamper(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "set-mppreference -disablerealtimemonitoring",
        "stop-service windefend", "sc stop windefend",
        "uninstall sentinelone", "stop-service crowdstrikefalconservice",
        "add-mppreference -exclusionpath", "tamper protection",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("local"))
    for src, grp in by_src:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R019",
            rule_name="Security Tool Tampering",
            severity=AlertSeverity.CRITICAL,
            description=f"{len(grp)} attempt(s) to disable, exclude or remove an endpoint security control on {src}",
            timestamp=ts,
            source_ip=None if src == "local" else str(src),
            event_count=len(grp),
            mitre_technique="T1562.001",
            mitre_tactic="Defense Evasion",
            tp_probability=0.94,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R020 — Inbound RDP Brute (T1021.001 / Lateral Movement)
# ---------------------------------------------------------------------------
def rule_r020_rdp_brute(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    rdp = df[
        ((df["port"].astype("Int64") == 3389) if "port" in df.columns else False)
        | df["event_type"].astype(str).str.lower().str.contains("rdp|terminal services", na=False, regex=True)
    ].copy() if "event_type" in df.columns else df.iloc[0:0]
    if rdp.empty:
        return alerts
    failed = rdp[rdp["status"].astype(str).str.upper().isin(["FAILED", "FAILURE", "DENIED"])]
    if failed.empty:
        return alerts
    by_src = failed.groupby(failed["source_ip"].fillna("unknown"))
    for src, grp in by_src:
        if len(grp) < 8 or src == "unknown":
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R020",
            rule_name="RDP Brute Force",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} failed RDP logon attempts from {src}",
            timestamp=ts,
            source_ip=str(src),
            event_count=len(grp),
            mitre_technique="T1021.001",
            mitre_tactic="Lateral Movement",
            tp_probability=0.93,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R021 — C2 Beaconing (regular interval egress) (T1071 / C&C)
# Look for periodic outbound connections from a host to the same destination.
# ---------------------------------------------------------------------------
def rule_r021_beaconing(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty:
        return alerts
    work = work[work["dest_ip"].notna() & work["source_ip"].notna()].copy()
    if work.empty:
        return alerts
    # Only consider external destinations
    work = work[work["dest_ip"].apply(_is_external_ip)]
    if work.empty:
        return alerts
    by_pair = work.groupby(["source_ip", "dest_ip"])
    for (src, dst), grp in by_pair:
        if len(grp) < 6:
            continue
        ts_sorted = grp["timestamp"].sort_values()
        deltas = ts_sorted.diff().dropna().dt.total_seconds()
        if deltas.empty:
            continue
        # Coefficient of variation low → very regular cadence
        mean = float(deltas.mean()) if not deltas.empty else 0.0
        std = float(deltas.std()) if not deltas.empty else 0.0
        if mean < 30 or mean > 3600:
            continue
        if std == 0 or (std / mean) > 0.25:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R021",
            rule_name="C2 Beaconing Suspected",
            severity=AlertSeverity.CRITICAL,
            description=f"{src} contacted {dst} {len(grp)} times at ~{int(mean)}s intervals (CV={std/mean:.2f})",
            timestamp=ts,
            source_ip=str(src),
            dest_ip=str(dst),
            event_count=len(grp),
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control",
            tp_probability=0.95,
            related_log_indices=list(grp.index),
            extra={"interval_seconds": int(mean), "cv": round(std / mean, 3)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R022 — Impossible Travel (T1078 / Initial Access)
# Same user, two distinct external source IPs within < 1h (geo-impossible).
# Without a real geo DB we approximate by counting distinct /16 networks.
# ---------------------------------------------------------------------------
def rule_r022_impossible_travel(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty or "user" not in work.columns:
        return alerts
    logins = work[
        work["event_type"].astype(str).str.lower().str.contains("login|auth|logon", na=False, regex=True)
        & (work["status"].astype(str).str.upper().isin(["SUCCESS", "SUCCEEDED", "OK"]))
        & work["user"].notna()
        & work["source_ip"].notna()
    ].copy()
    if logins.empty:
        return alerts
    def _net16(ip: str) -> str:
        parts = str(ip).split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else ip
    logins["net16"] = logins["source_ip"].apply(_net16)
    by_user = logins.sort_values("timestamp").groupby("user")
    for user, grp in by_user:
        nets = grp["net16"].tolist()
        ts_list = grp["timestamp"].tolist()
        flagged = False
        for i in range(1, len(grp)):
            if nets[i] != nets[i - 1] and ts_list[i] is not None and ts_list[i - 1] is not None:
                dt = (ts_list[i] - ts_list[i - 1]).total_seconds()
                if 0 < dt < 3600:
                    flagged = True
                    break
        if not flagged:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R022",
            rule_name="Impossible Travel / Geo Anomaly",
            severity=AlertSeverity.HIGH,
            description=f"User '{user}' authenticated from {grp['net16'].nunique()} distinct /16 networks within an hour",
            timestamp=ts,
            user=str(user),
            source_ip=str(grp["source_ip"].iloc[-1]),
            event_count=len(grp),
            mitre_technique="T1078",
            mitre_tactic="Initial Access",
            tp_probability=0.89,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R023 — Mass File Encryption (ransomware) (T1486 / Impact)
# ---------------------------------------------------------------------------
def rule_r023_ransomware(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    # Match either ransom extension events or vssadmin shadow-copy deletion.
    ext_hits = _raw_contains(df, [
        ".encrypted", ".locked", ".crypt", ".enc", ".ryk", ".lockbit",
        ".readme.txt", "how_to_decrypt", "decrypt_instructions",
    ])
    vss_hits = _raw_contains(df, [
        "vssadmin delete shadows", "wbadmin delete", "bcdedit /set",
        "wmic shadowcopy delete",
    ])
    if ext_hits.empty and vss_hits.empty:
        return alerts
    # Encryption signal must be voluminous to fire (>= 30 files), but VSS deletion
    # is high-confidence even alone.
    if not ext_hits.empty:
        by_src = ext_hits.groupby(ext_hits["source_ip"].fillna("local"))
        for src, grp in by_src:
            if len(grp) < 30:
                continue
            ts = _safe_min_ts(grp)
            if ts is None:
                continue
            alerts.append(Alert(
                alert_id=_new_alert_id(),
                rule_id="R023",
                rule_name="Mass File Encryption (Ransomware)",
                severity=AlertSeverity.CRITICAL,
                description=f"{len(grp)} ransom-extension or note files written on {src}",
                timestamp=ts,
                source_ip=None if src == "local" else str(src),
                event_count=len(grp),
                mitre_technique="T1486",
                mitre_tactic="Impact",
                tp_probability=0.97,
                related_log_indices=list(grp.index),
            ))
    if not vss_hits.empty:
        ts = _safe_min_ts(vss_hits)
        if ts is not None:
            alerts.append(Alert(
                alert_id=_new_alert_id(),
                rule_id="R023",
                rule_name="Shadow Copy Deletion (Ransomware Precursor)",
                severity=AlertSeverity.CRITICAL,
                description=f"{len(vss_hits)} volume-shadow / backup deletion command(s) executed",
                timestamp=ts,
                source_ip=str(vss_hits["source_ip"].dropna().iloc[0]) if vss_hits["source_ip"].dropna().size else None,
                event_count=len(vss_hits),
                mitre_technique="T1490",
                mitre_tactic="Impact",
                tp_probability=0.96,
                related_log_indices=list(vss_hits.index),
            ))
    return alerts


# ---------------------------------------------------------------------------
# R024 — SQL Injection Probe (T1190 / Initial Access)
# ---------------------------------------------------------------------------
def rule_r024_sql_injection(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "' or '1'='1", "' or 1=1--", "union select", "union all select",
        "sleep(", "benchmark(", "information_schema.tables",
        "xp_cmdshell", "convert(int,", "load_file(",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("unknown"))
    for src, grp in by_src:
        if src == "unknown" and len(grp) < 3:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R024",
            rule_name="SQL Injection Probe",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} SQL-injection payload pattern(s) seen from {src}",
            timestamp=ts,
            source_ip=None if src == "unknown" else str(src),
            event_count=len(grp),
            mitre_technique="T1190",
            mitre_tactic="Initial Access",
            tp_probability=0.91,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R025 — Web Shell / Suspicious User-Agent (T1505.003 / Persistence)
# ---------------------------------------------------------------------------
def rule_r025_web_shell(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    hits = _raw_contains(df, [
        "cmd.aspx", "cmd.jsp", "shell.php", "webshell.php",
        "c99.php", "r57.php", "/wp-admin/shell", "?cmd=",
        "user-agent: sqlmap", "user-agent: nikto", "user-agent: nmap",
        "user-agent: masscan", "user-agent: gobuster",
    ])
    if hits.empty:
        return alerts
    by_src = hits.groupby(hits["source_ip"].fillna("unknown"))
    for src, grp in by_src:
        if src == "unknown" and len(grp) < 3:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R025",
            rule_name="Web Shell or Recon Tooling",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} request(s) for web-shell paths or recon-tool user-agents from {src}",
            timestamp=ts,
            source_ip=None if src == "unknown" else str(src),
            event_count=len(grp),
            mitre_technique="T1505.003",
            mitre_tactic="Persistence",
            tp_probability=0.90,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
ALL_RULES: list[Callable[[pd.DataFrame], List[Alert]]] = [
    rule_r001_brute_force,
    rule_r002_port_scan,
    rule_r003_priv_esc,
    rule_r004_lateral,
    rule_r005_exfil,
    rule_r006_off_hours,
    rule_r007_new_admin,
    rule_r008_fuzzing,
    rule_r009_malicious_ip,
    rule_r010_multi_service,
    rule_r011_powershell,
    rule_r012_process_injection,
    rule_r013_lsass,
    rule_r014_dns_tunnel,
    rule_r015_cleartext_creds,
    rule_r016_lockout_storm,
    rule_r017_persistence,
    rule_r018_log_cleared,
    rule_r019_av_tamper,
    rule_r020_rdp_brute,
    rule_r021_beaconing,
    rule_r022_impossible_travel,
    rule_r023_ransomware,
    rule_r024_sql_injection,
    rule_r025_web_shell,
]


def run_all_rules(df: pd.DataFrame) -> List[Alert]:
    """Run every rule and return the merged alert list."""
    alerts: List[Alert] = []
    if df is None or df.empty:
        return alerts
    for rule in ALL_RULES:
        try:
            alerts.extend(rule(df))
        except Exception as exc:  # noqa: BLE001 — one bad rule shouldn't kill ingest
            import logging
            logging.getLogger("noctra.rules").exception(
                "Rule %s crashed: %s", rule.__name__, exc
            )
    return alerts
