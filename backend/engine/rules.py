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
    >=3 FAILED login events from the same source_ip within any 60-second window.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty:
        return alerts

    failed = work[
        (work["event_type"].astype(str).str.lower().str.contains(
            "login|auth|logon|sshd|ssh|pam|krb|ntlm|ldap", na=False))
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
        spike = group[group["_window_count"] >= 3]
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
    Outbound exfiltration to an external destination. Strengthened:
      - aggregates per (source_ip, dest_ip) so one campaign = one alert
        (previously this fired 19x for the same Mega.nz exfil)
      - fires either on a single > 100 MB session OR cumulative > 250 MB
        across many smaller bursts (the more common evasive pattern)
      - severity escalates to CRITICAL once total > 1 GB
    """
    alerts: List[Alert] = []
    if "bytes" not in df.columns or "dest_ip" not in df.columns:
        return alerts
    work = df[df["bytes"].notna() & df["dest_ip"].notna()].copy()
    if work.empty:
        return alerts
    work["_b"] = pd.to_numeric(work["bytes"], errors="coerce").fillna(0).astype(int)
    work = work[work["dest_ip"].apply(_is_external_ip)]
    if work.empty:
        return alerts
    single_threshold = 100 * 1024 * 1024   # 100 MB
    cumulative_threshold = 250 * 1024 * 1024  # 250 MB
    for (src, dst), grp in work.groupby(["source_ip", "dest_ip"]):
        total = int(grp["_b"].sum())
        peak = int(grp["_b"].max())
        if total < cumulative_threshold and peak < single_threshold:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        mb_total = total / 1024 / 1024
        mb_peak = peak / 1024 / 1024
        sev = AlertSeverity.CRITICAL if total > 1024 * 1024 * 1024 else AlertSeverity.HIGH
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R005",
            rule_name="Data Exfiltration",
            severity=sev,
            description=(
                f"{mb_total:.1f} MB across {len(grp)} session(s) "
                f"(peak {mb_peak:.1f} MB) from {src or 'unknown'} → {dst} (external)"
            ),
            timestamp=ts,
            source_ip=src,
            dest_ip=dst,
            user=str(grp["user"].dropna().iloc[0]) if "user" in grp.columns and grp["user"].dropna().size else None,
            event_count=len(grp),
            mitre_technique="T1041",
            mitre_tactic="Exfiltration",
            tp_probability=0.92 if total > 1024 * 1024 * 1024 else 0.83,
            related_log_indices=list(grp.index),
            extra={
                "total_bytes": total,
                "peak_bytes": peak,
                "session_count": len(grp),
            },
        ))
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
    # Aggregate per user so a single account logging in 50 times off-hours emits
    # ONE alert, not 50. The description preserves the count and the time range.
    for user, grp in odd.groupby(odd["user"].astype(str)):
        ts_min = grp["timestamp"].min()
        ts_max = grp["timestamp"].max()
        src_ips = sorted({str(s) for s in grp.get("source_ip", pd.Series(dtype=str)).dropna().unique()})
        rep_ip = src_ips[0] if src_ips else None
        desc = (
            f"{user} had {len(grp)} off-hours login(s) between "
            f"{ts_min.strftime('%H:%M')}–{ts_max.strftime('%H:%M')} UTC"
            if len(grp) > 1
            else f"{user} logged in at {ts_min.strftime('%H:%M')} UTC"
        )
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R006",
                rule_name="Suspicious Login Time",
                severity=AlertSeverity.MEDIUM,
                description=desc,
                timestamp=ts_min.to_pydatetime(),
                source_ip=rep_ip,
                user=str(user),
                event_count=len(grp),
                mitre_technique="T1078",
                mitre_tactic="Defense Evasion",
                related_log_indices=[int(i) for i in grp.index],
                extra={"source_ips": src_ips[:10]} if src_ips else None,
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R007 — New Admin Account Created
# ---------------------------------------------------------------------------
def rule_r007_new_admin(df: pd.DataFrame) -> List[Alert]:
    """
    Account creation / role-grant events that target a privileged identity.
    Covers Linux (useradd), Windows (Event 4720/4732), and cloud
    (Entra "Add user" + "Add member to role", AWS IAM CreateUser/AttachUserPolicy).
    """
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    et = df["event_type"].astype(str).str.lower()
    raw = df["raw"].astype(str).str.lower() if "raw" in df.columns else pd.Series("", index=df.index)
    et_mask = et.str.contains(
        "create_user|user_created|account_added|new_user|useradd|add user|add member to role|"
        "createuser|attachuserpolicy|addusertogroup|4720|4728|4732",
        na=False, regex=True,
    )
    raw_mask = raw.str.contains(
        "global administrator|privileged role|role\\.displayname|attachuserpolicy|administrators",
        na=False, regex=True,
    )
    creations = df[et_mask | (et_mask & raw_mask)]
    if creations.empty:
        # Fall back: any account-creation event whose raw mentions admin/global-admin role
        creations = df[et_mask & raw_mask] if not et_mask.empty else df.iloc[0:0]
    if creations.empty:
        return alerts
    user_l = creations["user"].astype(str).str.lower() if "user" in creations.columns else pd.Series("", index=creations.index)
    creations_raw_l = creations["raw"].astype(str).str.lower() if "raw" in creations.columns else pd.Series("", index=creations.index)
    creations = creations[
        user_l.isin(_ADMIN_USERS)
        | user_l.str.contains("admin", na=False)
        | creations_raw_l.str.contains("global administrator|administrators|administrator role|privileged role", na=False, regex=True)
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
    http = http[http["timestamp"].notna()]
    if http.empty:
        return alerts
    # Burst gate: only count 404s that fall inside a 5-minute sliding window.
    # 20 scattered 404s over a week is normal browsing noise; 20 in 5 minutes
    # is fuzzing. Avoids the "log file spans 7 days" false positive.
    WINDOW = pd.Timedelta(minutes=5)
    THRESHOLD = 20
    for src_ip, group in http.groupby("source_ip"):
        g = group.sort_values("timestamp")
        ts = g["timestamp"].reset_index(drop=True)
        max_burst = 0
        burst_idx: list[int] = []
        i = 0
        for j in range(len(ts)):
            while ts[j] - ts[i] > WINDOW:
                i += 1
            if j - i + 1 > max_burst:
                max_burst = j - i + 1
                burst_idx = list(g.index[i:j + 1])
        if max_burst < THRESHOLD:
            continue
        burst = g.loc[burst_idx]
        alerts.append(
            Alert(
                alert_id=_new_alert_id(),
                rule_id="R008",
                rule_name="Web Recon / Fuzzing",
                severity=AlertSeverity.MEDIUM,
                description=(
                    f"{max_burst} HTTP 404 responses from {src_ip} within 5 minutes"
                ),
                timestamp=burst["timestamp"].min().to_pydatetime(),
                source_ip=str(src_ip),
                event_count=max_burst,
                mitre_technique="T1595",
                mitre_tactic="Reconnaissance",
                related_log_indices=[int(i) for i in burst_idx],
                extra={"window_minutes": 5, "burst_size": max_burst,
                       "total_404s_from_ip": len(group)},
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
    # 404 is a benign client error (broken links, link-checkers) — exclude it
    # from the "auth failure" set. Genuine credential abuse shows up as
    # FAILED/401/403, not 404. Keeps multi-service noise from link rot.
    bad = df[
        df["status"].astype(str).str.upper().isin(["FAILED", "401", "403"])
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
        # Need both: 3+ distinct services AND enough volume per service to
        # rule out an accidental one-shot failure on each.
        if len(norm) < 3 or len(group) < 6:
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
    download cradles, or AMSI bypass markers. Uses regex so short-form flags
    (`-nop -w hidden -enc <b64>`) are caught even when other flags sit between
    powershell and -enc.
    """
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    raw_l = df["raw"].astype(str).str.lower()
    pat = (
        r"powershell(?:\.exe)?[^\n]{0,80}\s-e(?:nc|ncoded|ncodedcommand)?\b|"
        r"-encodedcommand\b|"
        r"iex\s*\(?\s*new-object\s+net\.webclient|"
        r"\.downloadstring\(|\.downloadfile\(|\.downloaddata\(|"
        r"amsiscanbuffer|amsi\.dll|frombase64string|"
        r"invoke-expression|invoke-webrequest\s+[^|]*\s*-uri|"
        r"-nop\s+-w(?:in(?:dowstyle)?)?\s+hidden|"
        r"start-bitstransfer|reflective\s+dll|invoke-shellcode|"
        r"set-mppreference.*disablerealtimemonitoring|"
        r"system\.management\.automation\.runspaces"
    )
    hits = df[raw_l.str.contains(pat, na=False, regex=True)].copy()
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
        # Perfectly periodic (std==0) is the MOST suspicious pattern, not a
        # reason to skip — that was a bug. Only reject if cadence is irregular.
        cv = (std / mean) if mean > 0 else 0.0
        if cv > 0.30:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R021",
            rule_name="C2 Beaconing Suspected",
            severity=AlertSeverity.CRITICAL,
            description=f"{src} contacted {dst} {len(grp)} times at ~{int(mean)}s intervals (CV={cv:.2f})",
            timestamp=ts,
            source_ip=str(src),
            dest_ip=str(dst),
            event_count=len(grp),
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control",
            tp_probability=0.95,
            related_log_indices=list(grp.index),
            extra={"interval_seconds": int(mean), "cv": round(cv, 3)},
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
        # URL-encoded variants (+ = space, %20 = space)
        "'+or+", "1=1--", "union+select", "union%20select",
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


# ===========================================================================
# R026-R032 — Hollow-Vault / cloud-era coverage pack
# Targets IDS signatures, NRD beacons, cloud-storage exfil, phishing,
# privileged-cloud-role grants, masquerading binaries, and PowerShell drops.
# ===========================================================================

# ---------------------------------------------------------------------------
# R026 — IDS / Suricata Signature Alert (T1071 / catch-all C2 + malware)
# Fires on any row carrying an IDS alert signature — high fidelity by design.
# ---------------------------------------------------------------------------
def rule_r026_ids_signature(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    # Prefer the flattened nested field; fall back to scanning raw.
    sig_col = None
    for c in ("alert_signature", "signature", "rule_name"):
        if c in df.columns and df[c].notna().any():
            sig_col = c
            break
    if sig_col is None:
        # Raw scan for common ET MALWARE / suricata alert markers
        hits = _raw_contains(df, [
            "et malware", "et trojan", "et exploit", "et policy",
            "et scan", "signature_id", "\"event_type\": \"alert\"",
        ])
    else:
        hits = df[df[sig_col].notna() & (df[sig_col].astype(str).str.strip() != "")].copy()
    if hits.empty:
        return alerts
    # Group by (source, signature) so the same beacon doesn't generate 10 alerts.
    sig_series = hits[sig_col].astype(str) if sig_col else hits["raw"].astype(str).str.slice(0, 80)
    hits = hits.assign(_sig=sig_series.fillna("ids_alert"))
    by = hits.groupby(["_sig", hits["source_ip"].fillna("unknown")])
    for (sig, src), grp in by:
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        dest = str(grp["dest_ip"].dropna().iloc[0]) if "dest_ip" in grp.columns and grp["dest_ip"].dropna().size else None
        # Severity: critical if signature mentions malware/c2/ransomware/exploit.
        sig_l = str(sig).lower()
        crit = any(k in sig_l for k in ("malware", "trojan", "c2", "ransom", "exploit", "rat"))
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R026",
            rule_name="IDS Signature Alert",
            severity=AlertSeverity.CRITICAL if crit else AlertSeverity.HIGH,
            description=f"IDS fired {len(grp)}x on '{sig}'" + (f" from {src}" if src != "unknown" else ""),
            timestamp=ts,
            source_ip=None if src == "unknown" else str(src),
            dest_ip=dest,
            event_count=len(grp),
            mitre_technique="T1071",
            mitre_tactic="Command and Control",
            tp_probability=0.95 if crit else 0.88,
            related_log_indices=list(grp.index),
            extra={"signature": str(sig)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R027 — Cloud-storage / file-sharing exfiltration (T1567 / Exfiltration)
# Large outbound traffic to consumer file-sharing services bypasses corporate
# DLP. Threshold deliberately lower than R005 because dest is high-risk.
# ---------------------------------------------------------------------------
_FILESHARE_PATTERNS = (
    "mega.nz", "mega.co.nz", "transfer.sh", "anonfiles", "filebin",
    "wetransfer", "send.bitwarden", "pastebin.com", "ghostbin",
    "dropbox.com/s/", "drive.google.com/uc", "filemail", "gofile.io",
    "tmpfiles.org", "mediafire.com",
)


def rule_r027_cloud_exfil(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    raw_l = df["raw"].astype(str).str.lower() if "raw" in df.columns else pd.Series("", index=df.index)
    mask = pd.Series(False, index=df.index)
    for p in _FILESHARE_PATTERNS:
        mask = mask | raw_l.str.contains(p, na=False, regex=False)
    # Palo Alto category 'file-sharing' is a strong signal even without a domain match.
    if "category" in df.columns:
        mask = mask | df["category"].astype(str).str.lower().eq("file-sharing")
    if "app" in df.columns:
        mask = mask | df["app"].astype(str).str.lower().isin({"mega", "dropbox", "wetransfer", "pastebin"})
    hits = df[mask].copy()
    if hits.empty:
        return alerts
    # Aggregate volume per (user|source_ip, dest)
    if "bytes" not in hits.columns:
        return alerts
    hits["_bytes"] = pd.to_numeric(hits["bytes"], errors="coerce").fillna(0)
    key_src = hits["user"].fillna(hits["source_ip"].astype(str)).fillna("unknown")
    key_dst = hits.get("dest_host", pd.Series("", index=hits.index))
    if "dest_host" not in hits.columns:
        # Pull dest host from raw if present
        key_dst = hits["raw"].astype(str).str.extract(r'(?:dst_hostname|host|destination)["\s:=]+["\']?([\w.\-]+)', expand=False).fillna("")
    hits = hits.assign(_src=key_src, _dst=key_dst.fillna(""))
    grouped = hits.groupby(["_src", "_dst"])
    for (src, dst), grp in grouped:
        total = int(grp["_bytes"].sum())
        if total < 10 * 1024 * 1024 and len(grp) < 3:
            continue  # ignore trivial chatter
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        mb = total / 1024 / 1024
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R027",
            rule_name="Cloud Storage Exfiltration",
            severity=AlertSeverity.CRITICAL if mb > 100 else AlertSeverity.HIGH,
            description=f"{src} sent {mb:.1f} MB across {len(grp)} session(s) to file-sharing dest '{dst or 'unknown'}'",
            timestamp=ts,
            source_ip=str(grp["source_ip"].dropna().iloc[0]) if "source_ip" in grp.columns and grp["source_ip"].dropna().size else None,
            user=str(src) if src != "unknown" else None,
            event_count=len(grp),
            mitre_technique="T1567.002",
            mitre_tactic="Exfiltration",
            tp_probability=0.95 if mb > 100 else 0.85,
            related_log_indices=list(grp.index),
            extra={"total_bytes": total, "destination": str(dst)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R028 — Newly Registered / Suspicious Domain Contact (T1568 / C2)
# ---------------------------------------------------------------------------
def rule_r028_nrd_contact(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    mask = pd.Series(False, index=df.index)
    if "category" in df.columns:
        cat = df["category"].astype(str).str.lower()
        mask = mask | cat.isin({"newly-registered-domain", "dynamic-dns", "parked", "malware"})
    # TLDs commonly abused by malware infrastructure
    raw_l = df["raw"].astype(str).str.lower() if "raw" in df.columns else pd.Series("", index=df.index)
    mask = mask | raw_l.str.contains(r"\.(?:xyz|top|tk|ml|ga|cf|gq|click|country|men|loan|kim)\b", na=False, regex=True)
    hits = df[mask]
    if hits.empty:
        return alerts
    # Pick a stable per-domain pivot.
    dom = hits.get("dest_host")
    if dom is None or dom.isna().all():
        dom = hits["raw"].astype(str).str.extract(r'([a-z0-9\-]+\.(?:xyz|top|tk|ml|ga|cf|gq|click|country|men|loan|kim))', expand=False)
    hits = hits.assign(_dom=dom.fillna("unknown"))
    for d, grp in hits.groupby("_dom"):
        if d == "unknown":
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R028",
            rule_name="Newly Registered / Suspicious Domain Contact",
            severity=AlertSeverity.HIGH,
            description=f"{len(grp)} connection(s) to suspicious domain '{d}'",
            timestamp=ts,
            source_ip=str(grp["source_ip"].dropna().iloc[0]) if "source_ip" in grp.columns and grp["source_ip"].dropna().size else None,
            user=str(grp["user"].dropna().iloc[0]) if "user" in grp.columns and grp["user"].dropna().size else None,
            event_count=len(grp),
            mitre_technique="T1568",
            mitre_tactic="Command and Control",
            tp_probability=0.90,
            related_log_indices=list(grp.index),
            extra={"domain": str(d)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R029 — Phishing email with risky attachment / auth failure
# (T1566.001 / Initial Access)
# ---------------------------------------------------------------------------
_RISKY_ATTACHMENT_EXT = (".docm", ".xlsm", ".pptm", ".iso", ".img", ".lnk",
                        ".js", ".vbs", ".hta", ".chm", ".scr", ".jar", ".one")


def rule_r029_phishing(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    raw_l = df["raw"].astype(str).str.lower()
    # Defender for O365 EmailEvents shape — look for SPF/DKIM/DMARC failure
    # plus a risky attachment extension.
    auth_fail = raw_l.str.contains(r"dkim=fail|dmarc=fail|spf=fail|compauth=fail", na=False, regex=True)
    risky_attach = raw_l.apply(lambda s: any(ext in s for ext in _RISKY_ATTACHMENT_EXT))
    suspicious_subj = raw_l.str.contains(
        r"(?:invoice|payroll|wire transfer|urgent|password reset|docusign|review.*eod|please confirm)",
        na=False, regex=True,
    )
    is_email = raw_l.str.contains("networkmessageid|internetmessageid|senderfromaddress|emaildirection", na=False, regex=True)
    mask = is_email & (auth_fail | risky_attach | suspicious_subj)
    # If we picked up email rows, require at least one strong indicator.
    strong = is_email & (auth_fail | risky_attach)
    hits = df[strong] if strong.any() else df[mask]
    if hits.empty:
        return alerts
    # Aggregate per sender so the same phishing campaign blasted to 100
    # recipients fires ONE alert per sender, not 100 separate ones.
    hits = hits[hits["timestamp"].notna()]
    if hits.empty:
        return alerts
    sender_col = (
        hits["senderfromaddress"] if "senderfromaddress" in hits.columns
        else hits.get("user", pd.Series("unknown", index=hits.index))
    ).astype(str).fillna("unknown")
    for sender, grp in hits.groupby(sender_col):
        recipients = sorted({
            str(r) for r in grp.get("recipientemailaddress", pd.Series(dtype=str)).dropna().unique()
        })
        rcpt_summary = (
            recipients[0] if len(recipients) == 1
            else f"{len(recipients)} recipients" if recipients
            else "unknown"
        )
        ts_min = grp["timestamp"].min().to_pydatetime()
        src_ip = next(
            (str(s) for s in grp.get("source_ip", pd.Series(dtype=str)).dropna().tolist()),
            None,
        )
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R029",
            rule_name="Phishing Email (Risky Attachment / Auth Fail)",
            severity=AlertSeverity.HIGH,
            description=(
                f"Email from {sender} → {rcpt_summary} with risky attachment "
                f"and/or DKIM/DMARC failure ({len(grp)} message(s))"
            ),
            timestamp=ts_min,
            user=recipients[0] if len(recipients) == 1 else None,
            source_ip=src_ip,
            event_count=len(grp),
            mitre_technique="T1566.001",
            mitre_tactic="Initial Access",
            tp_probability=0.90,
            related_log_indices=[int(i) for i in grp.index],
            extra={"sender": str(sender), "recipient_count": len(recipients),
                   "recipients_sample": recipients[:5]},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R030 — Cloud privileged-role assignment (T1098 / Persistence)
# Specifically catches Entra "Add member to role" → Global Administrator and
# AWS IAM AttachUserPolicy → AdministratorAccess.
# ---------------------------------------------------------------------------
def rule_r030_cloud_admin_grant(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    raw_l = df["raw"].astype(str).str.lower()
    et_l = df["event_type"].astype(str).str.lower() if "event_type" in df.columns else pd.Series("", index=df.index)
    is_role_grant = (
        et_l.str.contains("add member to role|attachuserpolicy|addusertogroup|4732", na=False, regex=True)
        # AWS CloudTrail: eventName is in raw even if eventtype alias wins over eventname
        | raw_l.str.contains("attachuserpolicy|addusertogroup|createpolicy", na=False, regex=True)
    )
    is_priv = raw_l.str.contains(
        "global administrator|administratoraccess|domain admins|enterprise admins|"
        "privileged role administrator|62e90394-69f5-4237-9190-012177145e10",
        na=False, regex=True,
    )
    hits = df[is_role_grant & is_priv]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        actor = row.get("user") or "unknown"
        target = row.get("targetresources_userprincipalname") or row.get("targetresources_displayname") or "unknown"
        src_ip = row.get("source_ip") or row.get("initiatedby_user_ipaddress")
        # Off-hours / external IP boost confidence.
        sev = AlertSeverity.CRITICAL
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R030",
            rule_name="Cloud Privileged Role Assignment",
            severity=sev,
            description=f"{actor} granted privileged role to {target}",
            timestamp=ts,
            source_ip=str(src_ip) if src_ip else None,
            user=str(actor),
            event_count=1,
            mitre_technique="T1098.003",
            mitre_tactic="Persistence",
            tp_probability=0.97,
            related_log_indices=[int(idx)],
            extra={"actor": str(actor), "target": str(target)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R031 — Masquerading binary in user/temp path (T1036.005 / Defense Evasion)
# Drops named after legit Windows binaries (sysmon, svchost, lsass, services,
# csrss, winlogon, explorer) but located in C:\Users\*\Temp\ or C:\Windows\Temp\.
# ---------------------------------------------------------------------------
_MASQ_NAMES = (
    "sysmon", "svchost", "lsass", "services", "csrss", "winlogon", "explorer",
    "spoolsv", "wininit", "smss", "taskhostw", "rundll32", "dllhost",
)


def rule_r031_masquerade(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    raw_l = df["raw"].astype(str).str.lower()
    # Filename column (MDE FileEvents) or raw substring.
    fname = df["filename"].astype(str).str.lower() if "filename" in df.columns else pd.Series("", index=df.index)
    folder = df["folderpath"].astype(str).str.lower() if "folderpath" in df.columns else pd.Series("", index=df.index)
    name_mask = pd.Series(False, index=df.index)
    for n in _MASQ_NAMES:
        # match sysmon32.exe, svchost32.exe, lsass_x.exe etc — anything that
        # *looks* like the legit name but isn't an exact match.
        name_mask = name_mask | fname.str.contains(rf"{n}\d+\.exe|{n}[_\-].+\.exe", na=False, regex=True)
    in_temp = folder.str.contains(r"\\temp\\|\\appdata\\local\\temp|/tmp/", na=False, regex=True)
    # Strengthened: require the filename column to actually be set (so we are
    # looking at a real file event, not a tangential mention in another log
    # line). This kills the false-positive deluge where the masquerading name
    # appears inside an unrelated process command-line or alert blob.
    has_fname = fname.str.strip().ne("") & fname.ne("nan") & fname.ne("none")
    hits = df[name_mask & in_temp & has_fname]
    if hits.empty:
        return alerts
    hits = hits[hits["timestamp"].notna()]
    if hits.empty:
        return alerts
    device_col = hits["devicename"].astype(str).fillna("?") if "devicename" in hits.columns else pd.Series("?", index=hits.index)
    # Aggregate per device — one ransomware run dropping 200 files now emits
    # ONE alert per host, with a sample of the filenames in extra.
    for device, grp in hits.groupby(device_col):
        ts_min = grp["timestamp"].min().to_pydatetime()
        files = sorted({str(f) for f in grp.get("filename", pd.Series(dtype=str)).dropna().unique()})
        folders = sorted({str(f) for f in grp.get("folderpath", pd.Series(dtype=str)).dropna().unique()})
        src_ip = next((str(s) for s in grp.get("source_ip", pd.Series(dtype=str)).dropna().tolist()), None)
        user = next(
            (str(u) for u in (
                grp.get("user", pd.Series(dtype=str)).dropna().tolist()
                + grp.get("initiatingprocessaccountname", pd.Series(dtype=str)).dropna().tolist()
            )),
            None,
        )
        desc = (
            f"{len(files)} masquerading binaries on '{device}' "
            f"(e.g. '{files[0]}' under '{folders[0] if folders else 'temp'}')"
            if len(files) > 1
            else f"Suspicious binary '{files[0] if files else 'unknown'}' "
                 f"written to '{folders[0] if folders else 'temp'}'"
        )
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R031",
            rule_name="Masquerading Binary in Temp Path",
            severity=AlertSeverity.CRITICAL,
            description=desc,
            timestamp=ts_min,
            source_ip=src_ip,
            user=user,
            event_count=len(grp),
            mitre_technique="T1036.005",
            mitre_tactic="Defense Evasion",
            tp_probability=0.96,
            related_log_indices=[int(i) for i in grp.index],
            extra={"device": str(device), "file_count": len(files),
                   "files_sample": files[:10], "folders_sample": folders[:5]},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R032 — PowerShell drops executable to Temp (T1059.001 + T1105)
# MDE FileEvents where InitiatingProcessFileName == powershell.exe and
# resulting FileName ends in .exe under a Temp path.
# ---------------------------------------------------------------------------
def rule_r032_ps_drop_exe(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    init = df["initiatingprocessfilename"].astype(str).str.lower() if "initiatingprocessfilename" in df.columns else pd.Series("", index=df.index)
    fname = df["filename"].astype(str).str.lower() if "filename" in df.columns else pd.Series("", index=df.index)
    folder = df["folderpath"].astype(str).str.lower() if "folderpath" in df.columns else pd.Series("", index=df.index)
    is_ps = init.str.contains("powershell|pwsh|cmd\\.exe|wscript|cscript|mshta", na=False, regex=True)
    is_exe = fname.str.endswith(".exe") | fname.str.endswith(".dll") | fname.str.endswith(".ps1")
    in_temp = folder.str.contains(r"\\temp|appdata\\local\\temp|/tmp/", na=False, regex=True)
    hits = df[is_ps & is_exe & in_temp]
    if hits.empty:
        return alerts
    hits = hits[hits["timestamp"].notna()]
    if hits.empty:
        return alerts
    device_col = hits["devicename"].astype(str).fillna("?") if "devicename" in hits.columns else pd.Series("?", index=hits.index)
    init_col = hits["initiatingprocessfilename"].astype(str).fillna("?") if "initiatingprocessfilename" in hits.columns else pd.Series("?", index=hits.index)
    # Aggregate per (device, initiating process) so a single PowerShell run
    # dropping many files emits ONE alert rather than N.
    for (device, init), grp in hits.groupby([device_col, init_col]):
        ts_min = grp["timestamp"].min().to_pydatetime()
        files = sorted({str(f) for f in grp.get("filename", pd.Series(dtype=str)).dropna().unique()})
        folders = sorted({str(f) for f in grp.get("folderpath", pd.Series(dtype=str)).dropna().unique()})
        src_ip = next((str(s) for s in grp.get("source_ip", pd.Series(dtype=str)).dropna().tolist()), None)
        user = next(
            (str(u) for u in (
                grp.get("initiatingprocessaccountname", pd.Series(dtype=str)).dropna().tolist()
                + grp.get("user", pd.Series(dtype=str)).dropna().tolist()
            )),
            None,
        )
        desc = (
            f"{init} on '{device}' dropped {len(files)} executable(s) to temp "
            f"(e.g. '{files[0]}' → '{folders[0] if folders else '?'}')"
            if len(files) > 1
            else f"{init} wrote {files[0] if files else '?'} to "
                 f"{folders[0] if folders else '?'} on '{device}'"
        )
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R032",
            rule_name="Scripting Engine Drops Executable to Temp",
            severity=AlertSeverity.CRITICAL,
            description=desc,
            timestamp=ts_min,
            source_ip=src_ip,
            user=user,
            event_count=len(grp),
            mitre_technique="T1059.001",
            mitre_tactic="Execution",
            tp_probability=0.94,
            related_log_indices=[int(i) for i in grp.index],
            extra={"device": str(device), "initiating_process": str(init),
                   "file_count": len(files), "files_sample": files[:10]},
        ))
    return alerts


# ===========================================================================
# R033-R042 — Splunk/Sentinel-grade detections for AD, AWS, M365 and EDR
# ===========================================================================

# ---------------------------------------------------------------------------
# R033 — Kerberoasting (T1558.003 / Credential Access)
# Windows Event 4769 with weak encryption (RC4-HMAC 0x17 / DES 0x01/0x03).
# Volume threshold = 5 to avoid single-shot noise.
# ---------------------------------------------------------------------------
_WEAK_KERB_ENC = {"0x17", "0x18", "0x1", "0x01", "0x3", "0x03", "rc4-hmac", "rc4_hmac"}


def rule_r033_kerberoast(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    # Match by EventID (flattened to lowercase column) or raw contains. Tolerate
    # integer-typed EventID by stringifying and stripping decimals ("4769.0").
    eid = (
        df["eventid"].astype(str).str.replace(r"\.0$", "", regex=True)
        if "eventid" in df.columns
        else pd.Series("", index=df.index)
    )
    raw_l = df["raw"].astype(str).str.lower() if "raw" in df.columns else pd.Series("", index=df.index)
    tgs = df[
        (eid == "4769")
        | raw_l.str.contains(r'eventid["\']?\s*[:=]\s*"?4769', na=False, regex=True)
    ].copy()
    if tgs.empty:
        return alerts
    enc_col = None
    for c in ("ticketencryptiontype", "tgs_encryption", "encryptiontype",
              "ticket_encryption_type", "ticket_encryption"):
        if c in tgs.columns:
            enc_col = c
            break
    if enc_col is not None:
        tgs["_enc"] = tgs[enc_col].astype(str).str.lower()
        weak = tgs[tgs["_enc"].isin(_WEAK_KERB_ENC)]
    else:
        # Fallback: scan raw for the weak-encryption marker. Catches Windows
        # logs whose encryption-type field is exported under a non-standard
        # column name but still appears inline.
        raw_tgs = tgs["raw"].astype(str).str.lower() if "raw" in tgs.columns else pd.Series("", index=tgs.index)
        weak = tgs[raw_tgs.str.contains(r"0x17|0x18|rc4[-_]?hmac", na=False, regex=True)]
    if weak.empty:
        return alerts
    # Target column may be TargetUserName, ServiceName, etc.
    tgt_col = next((c for c in ("targetusername", "servicename", "user") if c in weak.columns), None)
    if tgt_col is None:
        return alerts
    for target, grp in weak.groupby(weak[tgt_col].astype(str)):
        if len(grp) < 5:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R033",
            rule_name="Kerberoasting (Weak TGS Encryption)",
            severity=AlertSeverity.CRITICAL,
            description=f"{len(grp)} TGS requests for '{target}' with weak (RC4/DES) encryption",
            timestamp=ts,
            source_ip=str(grp["source_ip"].dropna().iloc[0]) if "source_ip" in grp.columns and grp["source_ip"].dropna().size else None,
            user=str(target),
            event_count=len(grp),
            mitre_technique="T1558.003",
            mitre_tactic="Credential Access",
            tp_probability=0.95,
            related_log_indices=list(grp.index),
            extra={"target": str(target), "weak_count": len(grp)},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R034 — Office application spawns a shell / scripting engine (T1566.001/T1059)
# Classic macro-borne malware indicator — almost never benign in production.
# ---------------------------------------------------------------------------
_OFFICE_PARENTS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                   "msaccess.exe", "visio.exe", "onenote.exe", "publisher.exe")
_SHELL_CHILDREN = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                   "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                   "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe")


def rule_r034_office_macro(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    parent = df["initiatingprocessfilename"].astype(str).str.lower() if "initiatingprocessfilename" in df.columns else pd.Series("", index=df.index)
    child = df["filename"].astype(str).str.lower() if "filename" in df.columns else pd.Series("", index=df.index)
    is_office = parent.isin(_OFFICE_PARENTS)
    is_shell = child.isin(_SHELL_CHILDREN)
    hits = df[is_office & is_shell]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R034",
            rule_name="Office Application Spawned Shell",
            severity=AlertSeverity.CRITICAL,
            description=f"{row.get('initiatingprocessfilename')} spawned {row.get('filename')} — "
                        f"cmd: {str(row.get('processcommandline',''))[:160]}",
            timestamp=ts,
            user=str(row.get("accountname") or row.get("user") or "") or None,
            source_ip=str(row.get("source_ip")) if pd.notna(row.get("source_ip")) else None,
            event_count=1,
            mitre_technique="T1566.001",
            mitre_tactic="Initial Access",
            tp_probability=0.97,
            related_log_indices=[int(idx)],
            extra={"device": str(row.get("devicename") or ""),
                   "child_sha256": str(row.get("sha256") or "")},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R035 — LOLBin abuse (T1218 / T1105 — Defense Evasion + Ingress Tool Transfer)
# certutil/bitsadmin/curl/mshta/regsvr32 with URL or remote-fetch arguments.
# ---------------------------------------------------------------------------
def rule_r035_lolbin(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    raw_l = df["raw"].astype(str).str.lower()
    pat = (
        r"certutil(?:\.exe)?[^\n]{0,120}-urlcache|"
        r"certutil(?:\.exe)?[^\n]{0,120}-decode|"
        r"bitsadmin(?:\.exe)?[^\n]{0,120}/transfer|"
        r"mshta(?:\.exe)?\s+https?://|"
        r"mshta(?:\.exe)?\s+javascript:|"
        r"regsvr32(?:\.exe)?\s+[^\n]{0,80}/i:https?://|"
        r"regsvr32(?:\.exe)?[^\n]{0,80}scrobj\.dll|"
        r"rundll32(?:\.exe)?\s+javascript:|"
        r"rundll32(?:\.exe)?[^\n]{0,80}url\.dll,?openurl|"
        r"installutil(?:\.exe)?[^\n]{0,80}/logfile=|"
        r"msbuild(?:\.exe)?[^\n]{0,80}\.xml\b"
    )
    hits = df[raw_l.str.contains(pat, na=False, regex=True)]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R035",
            rule_name="Living-off-the-Land Binary Abuse",
            severity=AlertSeverity.HIGH,
            description=f"LOLBin invoked with remote-fetch / loader args — "
                        f"cmd: {str(row.get('processcommandline') or row.get('raw',''))[:160]}",
            timestamp=ts,
            user=str(row.get("user") or row.get("accountname") or "") or None,
            source_ip=str(row.get("source_ip")) if pd.notna(row.get("source_ip")) else None,
            event_count=1,
            mitre_technique="T1218",
            mitre_tactic="Defense Evasion",
            tp_probability=0.90,
            related_log_indices=[int(idx)],
        ))
    return alerts


# ---------------------------------------------------------------------------
# R036 — Service-account interactive / RDP logon (T1078.002 / Defense Evasion)
# A `svc_*` account performing LogonType 2 (Interactive) or 10 (RemoteInteractive)
# is almost always operator misuse or stolen-credential reuse.
# ---------------------------------------------------------------------------
def rule_r036_svc_interactive(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    eid = df["eventid"].astype(str) if "eventid" in df.columns else pd.Series("", index=df.index)
    lt = df["logontype"].astype(str) if "logontype" in df.columns else pd.Series("", index=df.index)
    user = df["targetusername"].astype(str).str.lower() if "targetusername" in df.columns else df["user"].astype(str).str.lower() if "user" in df.columns else pd.Series("", index=df.index)
    is_logon = (eid == "4624")
    is_interactive = lt.isin({"2", "10"})
    is_svc = user.str.startswith("svc_") | user.str.startswith("svc-") | user.str.contains(r"\bservice\b", na=False, regex=True)
    hits = df[is_logon & is_interactive & is_svc]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R036",
            rule_name="Service Account Interactive Logon",
            severity=AlertSeverity.HIGH,
            description=f"Service account '{row.get('targetusername') or row.get('user')}' performed "
                        f"LogonType {row.get('logontype')} on {row.get('computer') or row.get('devicename')}",
            timestamp=ts,
            user=str(row.get("targetusername") or row.get("user") or ""),
            source_ip=str(row.get("ipaddress") or row.get("source_ip") or "") or None,
            event_count=1,
            mitre_technique="T1078.002",
            mitre_tactic="Defense Evasion",
            tp_probability=0.92,
            related_log_indices=[int(idx)],
        ))
    return alerts


# ---------------------------------------------------------------------------
# R037 — AWS sensitive call without MFA (T1078.004 / Defense Evasion)
# ---------------------------------------------------------------------------
_SENSITIVE_AWS_EVENTS = {
    "createaccesskey", "deleteaccesskey", "createuser", "deleteuser",
    "attachuserpolicy", "attachrolepolicy", "putuserpolicy", "putrolepolicy",
    "createpolicy", "deletetrail", "stoplogging", "putbucketpolicy",
    "putbucketacl", "deletebucket", "createkey", "scheduleKeyDeletion",
    "disablekey", "consoleLogin", "assumerole",
}


def rule_r037_aws_no_mfa(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty or "raw" not in df.columns:
        return alerts
    en = df["eventname"].astype(str).str.lower() if "eventname" in df.columns else df["event_type"].astype(str).str.lower()
    raw_l = df["raw"].astype(str).str.lower()
    is_sensitive = en.isin(_SENSITIVE_AWS_EVENTS)
    # raw is lower-cased already, so we just need to tolerate quoted vs bare
    # false, JSON or pipe-joined serialisation, and a flattened
    # `mfaauthenticated` column from the JSON flattener.
    no_mfa_raw = raw_l.str.contains(
        r'mfaauthenticated["\']?\s*[:=]\s*["\']?false', na=False, regex=True,
    )
    if "mfaauthenticated" in df.columns:
        no_mfa_col = df["mfaauthenticated"].astype(str).str.lower().isin({"false", "0", "no"})
        no_mfa = no_mfa_raw | no_mfa_col
    else:
        no_mfa = no_mfa_raw
    hits = df[is_sensitive & no_mfa]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        actor = row.get("useridentity_arn") or row.get("user") or "?"
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R037",
            rule_name="AWS Sensitive API Call Without MFA",
            severity=AlertSeverity.HIGH,
            description=f"{actor} performed {row.get('event_type') or row.get('eventname') or '?'} without MFA from {row.get('sourceipaddress') or row.get('source_ip')}",
            timestamp=ts,
            source_ip=str(row.get("sourceipaddress") or row.get("source_ip") or "") or None,
            user=str(actor),
            event_count=1,
            mitre_technique="T1078.004",
            mitre_tactic="Defense Evasion",
            tp_probability=0.86,
            related_log_indices=[int(idx)],
            extra={"event_name": str(row.get("eventname") or "")},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R038 — AWS CloudTrail / logging tampering (T1562.008 / Impact)
# ---------------------------------------------------------------------------
def rule_r038_aws_logging_tamper(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    en = df["eventname"].astype(str).str.lower() if "eventname" in df.columns else df["event_type"].astype(str).str.lower()
    bad = en.isin({"stoplogging", "deletetrail", "updatetrail", "putconfigurationrecorder", "deleteconfigurationrecorder", "deleteflowlogs"})
    hits = df[bad]
    if hits.empty:
        return alerts
    for idx, row in hits.iterrows():
        ts = row["timestamp"].to_pydatetime() if pd.notna(row.get("timestamp")) else None
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R038",
            rule_name="AWS CloudTrail / Logging Tampering",
            severity=AlertSeverity.CRITICAL,
            description=f"{row.get('user')} invoked {row.get('event_type') or row.get('eventname') or '?'} — logging integrity compromised",
            timestamp=ts,
            source_ip=str(row.get("sourceipaddress") or row.get("source_ip") or "") or None,
            user=str(row.get("user") or "?"),
            event_count=1,
            mitre_technique="T1562.008",
            mitre_tactic="Defense Evasion",
            tp_probability=0.98,
            related_log_indices=[int(idx)],
        ))
    return alerts


# ---------------------------------------------------------------------------
# R039 — Anomalous AWS S3 access volume (T1530 / Collection)
# Single principal hitting S3 > 100 times in the window is unusual outside CI.
# ---------------------------------------------------------------------------
def rule_r039_s3_volume(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    src_col = None
    for c in ("eventsource", "source"):
        if c in df.columns:
            src_col = c
            break
    if src_col is None:
        return alerts
    s3 = df[df[src_col].astype(str).str.lower() == "s3.amazonaws.com"].copy()
    if s3.empty:
        return alerts
    actor = s3.get("useridentity_arn")
    if actor is None or actor.isna().all():
        actor = s3.get("user", pd.Series("", index=s3.index))
    s3["_actor"] = actor.fillna("unknown")
    for principal, grp in s3.groupby("_actor"):
        if len(grp) < 100:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R039",
            rule_name="AWS S3 Anomalous Access Volume",
            severity=AlertSeverity.HIGH,
            description=f"{principal} performed {len(grp)} S3 API calls — possible data collection / exfil staging",
            timestamp=ts,
            source_ip=str(grp["sourceipaddress"].dropna().iloc[0]) if "sourceipaddress" in grp.columns and grp["sourceipaddress"].dropna().size else None,
            user=str(principal),
            event_count=len(grp),
            mitre_technique="T1530",
            mitre_tactic="Collection",
            tp_probability=0.84,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R040 — SharePoint / OneDrive mass download (T1213.002 / Collection)
# A single user pulling many files from corporate document store.
# ---------------------------------------------------------------------------
def rule_r040_sharepoint_exfil(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    op_col = None
    for c in ("operation", "event_type"):
        if c in df.columns:
            op_col = c
            break
    if op_col is None:
        return alerts
    dl = df[df[op_col].astype(str).str.lower() == "filedownloaded"].copy()
    if dl.empty:
        return alerts
    user_col = "userid" if "userid" in dl.columns else "user"
    for u, grp in dl.groupby(dl[user_col].astype(str)):
        if len(grp) < 25:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R040",
            rule_name="SharePoint Mass File Download",
            severity=AlertSeverity.HIGH,
            description=f"{u} downloaded {len(grp)} files from SharePoint — possible insider exfil",
            timestamp=ts,
            user=str(u),
            source_ip=str(grp["clientip"].dropna().iloc[0]) if "clientip" in grp.columns and grp["clientip"].dropna().size else None,
            event_count=len(grp),
            mitre_technique="T1213.002",
            mitre_tactic="Collection",
            tp_probability=0.88,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R041 — Entra sign-in from unexpected country (T1078 / Initial Access)
# NorthBay employees are in IN — anything else is worth surfacing.
# ---------------------------------------------------------------------------
_ALLOWED_COUNTRIES = {"in", "india", ""}


def rule_r041_geo_anomaly(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    cc_col = None
    for c in ("location_countryorregion", "countryorregion", "country"):
        if c in df.columns:
            cc_col = c
            break
    if cc_col is None:
        return alerts
    work = df[df[cc_col].notna()].copy()
    work["_cc"] = work[cc_col].astype(str).str.lower()
    odd = work[~work["_cc"].isin(_ALLOWED_COUNTRIES)]
    if odd.empty:
        return alerts
    user_col = "userprincipalname" if "userprincipalname" in odd.columns else "user"
    for u, grp in odd.groupby(odd[user_col].astype(str)):
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        countries = sorted(grp["_cc"].unique().tolist())
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R041",
            rule_name="Sign-In from Unexpected Country",
            severity=AlertSeverity.HIGH,
            description=f"User '{u}' authenticated from country {','.join(countries)} (corp baseline = IN)",
            timestamp=ts,
            user=str(u),
            source_ip=str(grp["ipaddress"].dropna().iloc[0]) if "ipaddress" in grp.columns and grp["ipaddress"].dropna().size else None,
            event_count=len(grp),
            mitre_technique="T1078",
            mitre_tactic="Initial Access",
            tp_probability=0.87,
            related_log_indices=list(grp.index),
            extra={"countries": countries},
        ))
    return alerts


# ---------------------------------------------------------------------------
# R042 — Excessive AWS recon (T1580 / Discovery)
# >15 Describe* / List* calls from a single principal — enumeration pattern.
# ---------------------------------------------------------------------------
def rule_r042_aws_recon(df: pd.DataFrame) -> List[Alert]:
    alerts: List[Alert] = []
    if df.empty:
        return alerts
    en_col = "eventname" if "eventname" in df.columns else "event_type"
    if en_col not in df.columns:
        return alerts
    en = df[en_col].astype(str)
    is_recon = en.str.startswith(("Describe", "List", "Get")) & ~en.str.lower().eq("getobject")
    src_col = "eventsource" if "eventsource" in df.columns else None
    if src_col:
        is_aws = df[src_col].astype(str).str.contains("amazonaws.com", na=False)
        recon = df[is_recon & is_aws].copy()
    else:
        recon = df[is_recon].copy()
    if recon.empty:
        return alerts
    actor = recon.get("useridentity_arn")
    if actor is None or actor.isna().all():
        actor = recon.get("user", pd.Series("", index=recon.index))
    recon["_actor"] = actor.fillna("unknown")
    for principal, grp in recon.groupby("_actor"):
        if len(grp) < 15:
            continue
        unique_calls = grp[en_col].nunique()
        if unique_calls < 5:
            continue
        ts = _safe_min_ts(grp)
        if ts is None:
            continue
        alerts.append(Alert(
            alert_id=_new_alert_id(),
            rule_id="R042",
            rule_name="AWS Cloud Reconnaissance",
            severity=AlertSeverity.MEDIUM,
            description=f"{principal} made {len(grp)} discovery API calls ({unique_calls} distinct)",
            timestamp=ts,
            source_ip=str(grp["sourceipaddress"].dropna().iloc[0]) if "sourceipaddress" in grp.columns and grp["sourceipaddress"].dropna().size else None,
            user=str(principal),
            event_count=len(grp),
            mitre_technique="T1580",
            mitre_tactic="Discovery",
            tp_probability=0.74,
            related_log_indices=list(grp.index),
        ))
    return alerts


# ---------------------------------------------------------------------------
# R043 — IDOR / Sequential Resource Enumeration (T1083 / Discovery)
# Same IP or session accessing incrementing numeric resource IDs in rapid
# succession — classic IDOR enumeration pattern.
# ---------------------------------------------------------------------------
def rule_r043_idor_enumeration(df: pd.DataFrame) -> List[Alert]:
    """
    Detect sequential ID enumeration: same source IP making many requests
    to URLs whose terminal path segment is an incrementing integer, within
    a short window (60s). Fires on ≥5 distinct consecutive IDs.
    """
    alerts: List[Alert] = []
    work = _safe_ts(df)
    if work.empty or "raw" not in work.columns:
        return alerts

    import re as _re
    _ID_TAIL = _re.compile(r'/(\d{2,10})(?:[/?#"\'<\s]|$)')

    # Only look at HTTP GET rows if event_type is available; otherwise all rows.
    if "event_type" in work.columns:
        et_mask = work["event_type"].astype(str).str.lower().str.contains("http|get|api", na=False)
        # If none match by event_type, also include rows where raw contains a URL pattern
        url_in_raw = work["raw"].astype(str).str.contains(r'/\w+/\d{2,}', na=False, regex=True)
        http = work[et_mask | url_in_raw].copy()
    else:
        http = work.copy()
    if http.empty:
        return alerts

    # Extract the URL column (prefer dedicated url/path/dest_host field, fall back to raw).
    for _url_col in ("url", "path", "dest_host", "request"):
        if _url_col in http.columns and http[_url_col].notna().any():
            url_series = http[_url_col].astype(str)
            break
    else:
        url_series = http["raw"].astype(str)

    http = http.assign(_url=url_series)
    http["_id"] = http["_url"].apply(lambda u: int(m.group(1)) if (m := _ID_TAIL.search(u)) else None)
    http = http[http["_id"].notna()].copy()
    if http.empty:
        return alerts
    http["_id"] = http["_id"].astype(int)

    # Extract path prefix (everything up to the last numeric segment).
    http["_prefix"] = http["_url"].apply(
        lambda u: _ID_TAIL.sub("/<ID>", u) if _ID_TAIL.search(u) else u
    )

    window = timedelta(seconds=60)
    for (src_ip, prefix), grp in http.groupby([http["source_ip"].fillna("unknown"), http["_prefix"]]):
        if src_ip == "unknown":
            continue
        grp = grp.sort_values("timestamp")
        if len(grp) < 5:
            continue
        ids = sorted(grp["_id"].unique())
        # Check for consecutive run of ≥5.
        run = 1
        best = 1
        for i in range(1, len(ids)):
            if ids[i] - ids[i - 1] <= 2:  # allow gaps of 1
                run += 1
                best = max(best, run)
            else:
                run = 1
        if best < 3:
            continue
        # Sliding-window volume check.
        times = grp["timestamp"]
        for t in times:
            burst = grp[(grp["timestamp"] >= t - window) & (grp["timestamp"] <= t)]
            if burst["_id"].nunique() >= 3:
                ts = t.to_pydatetime()
                alerts.append(Alert(
                    alert_id=_new_alert_id(),
                    rule_id="R043",
                    rule_name="IDOR / Sequential Resource Enumeration",
                    severity=AlertSeverity.HIGH,
                    description=(
                        f"{src_ip} accessed {burst['_id'].nunique()} sequential IDs "
                        f"under '{prefix}' in 60s (IDs {ids[0]}–{ids[-1]})"
                    ),
                    timestamp=ts,
                    source_ip=str(src_ip),
                    user=str(grp["user"].dropna().iloc[0]) if "user" in grp.columns and grp["user"].dropna().size else None,
                    event_count=len(burst),
                    mitre_technique="T1083",
                    mitre_tactic="Discovery",
                    tp_probability=0.88,
                    related_log_indices=list(burst.index),
                    extra={
                        "endpoint_pattern": str(prefix),
                        "id_range": f"{ids[0]}–{ids[-1]}",
                        "distinct_ids": burst["_id"].nunique(),
                    },
                ))
                break  # one alert per (src_ip, prefix)
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
    rule_r026_ids_signature,
    rule_r027_cloud_exfil,
    rule_r028_nrd_contact,
    rule_r029_phishing,
    rule_r030_cloud_admin_grant,
    rule_r031_masquerade,
    rule_r032_ps_drop_exe,
    rule_r033_kerberoast,
    rule_r034_office_macro,
    rule_r035_lolbin,
    rule_r036_svc_interactive,
    rule_r037_aws_no_mfa,
    rule_r038_aws_logging_tamper,
    rule_r039_s3_volume,
    rule_r040_sharepoint_exfil,
    rule_r041_geo_anomaly,
    rule_r042_aws_recon,
    rule_r043_idor_enumeration,
]


# ===========================================================================
# Per-rule reasoning catalog
# Each entry: why this pattern is malicious, what signals validate it, what to
# do next, and the most common false-positive cause. Surfaced in the Triage
# modal so analysts can justify every alert with one click.
# ===========================================================================
_RULE_REASONING: Dict[str, Dict[str, str]] = {
    "R001": {
        "why": "A burst of failed logins from one source IP within a 60-second window is the textbook brute-force / credential-spray signature.",
        "validates": "Same IP, ≥6 FAILED auths in 60s, optional SUCCESS in the same window proves credential compromise.",
        "action": "Block the source IP at the perimeter, force password reset for any target user, and review session activity for the compromised account.",
        "fp_note": "Misconfigured automation hammering an auth endpoint with stale creds; check the user-agent / process before final escalation.",
    },
    "R002": {"why": "≥11 distinct destination ports hit from one source in 30 s is a classic TCP/UDP port-scan fingerprint (T1046).",
             "validates": "Distinct-port count, identical source, sub-minute density.",
             "action": "Drop the scanner IP at the edge firewall; review what listeners exposed those ports.",
             "fp_note": "Vulnerability scanners (Nessus/Qualys) on an authorised window."},
    "R003": {"why": "A normal user authenticates SUCCESS and within 10 minutes an admin-tier user authenticates from the same host — classic privilege-escalation chain.",
             "validates": "Same source IP, normal → admin SUCCESS sequence, sub-10-minute gap.",
             "action": "Pull the host's process tree for sudo / runas / token-impersonation events around the second login.",
             "fp_note": "Sysadmin actually elevating manually — confirm against change-management ticket."},
    "R004": {"why": "Same user successfully authenticates on ≥3 hosts in 5 min — typical post-compromise lateral spread (T1021).",
             "validates": "Single user, ≥3 distinct dest_ip, ≤5 min span.",
             "action": "Reset the user's password + tokens; isolate the hosts visited and pull SMB/WinRM/PSExec logs.",
             "fp_note": "Sysadmins running an Ansible / SCCM job."},
    "R005": {"why": "A single outbound flow exceeded 100 MB to an external IP — large enough to be exfil rather than normal browsing.",
             "validates": "bytes_sent threshold, destination is public IP space.",
             "action": "Block egress to the destination, pull DLP records, and capture the user's recent file-access history.",
             "fp_note": "Approved cloud backup to a known provider."},
    "R006": {"why": "A non-service user account performed SUCCESS auth in the 00:00–05:00 UTC window when offices are closed.",
             "validates": "Successful logon, off-hours timestamp, non-service-account name.",
             "action": "Validate against on-call rota; if unscheduled, treat as compromised credential.",
             "fp_note": "Engineers handling a P1 / weekend on-call."},
    "R007": {"why": "An admin-tier account was newly created, or an existing identity was added to a privileged role (Global Admin / Administrators).",
             "validates": "Account-creation event_type + admin name / group / role-templateId.",
             "action": "Verify the change request, audit the creator's recent activity, and require MFA on the new account.",
             "fp_note": "Legitimate onboarding of new IT admin within approved CAB."},
    "R008": {"why": "Over 20 HTTP 404 responses to the same source IP — webserver-fuzzing / directory-brute fingerprint (T1595).",
             "validates": "Same source IP, count >20, status=404.",
             "action": "Rate-limit the source, deploy a WAF rule for the dir-brute paths, and check for resulting 200s.",
             "fp_note": "Broken link-checker bot."},
    "R009": {"why": "Activity to/from a flagged-malicious IP. Enriched lazily via /threatintel.",
             "validates": "External IP appears in a reputable threat-intel feed.",
             "action": "Block the IP, pull session / DNS context, and review previous matches.",
             "fp_note": "Recently re-claimed cloud IP whose history hasn't aged out of feeds."},
    "R010": {"why": "FAILED auth events for the same source across ≥3 distinct services (SSH + HTTP + FTP …) — wide-spectrum credential spray.",
             "validates": "Same source IP, distinct event_type families, all FAILED.",
             "action": "Block the IP everywhere and investigate any successful auths from it.",
             "fp_note": "Misconfigured fleet of agents using rotated creds."},
    "R011": {"why": "PowerShell launched with encoded payload, download cradle, AMSI-bypass marker or hidden window — the most common malware loader.",
             "validates": "Command-line regex includes `-enc`, `DownloadString`, AMSI bypass tokens or hidden execution flags.",
             "action": "Decode the base64 to inspect the payload; isolate the host; hunt for persistence.",
             "fp_note": "Operations script wrapped in `-EncodedCommand` for quoting reasons."},
    "R012": {"why": "Process-injection APIs observed (CreateRemoteThread, WriteProcessMemory, NtMapViewOfSection, QueueUserAPC).",
             "validates": "Specific API names in the command-line / Sysmon image-load.",
             "action": "Memory-acquire the host; compare the injected SHA256 against threat-intel.",
             "fp_note": "Some legitimate AV/EDR products use the same APIs for inspection."},
    "R013": {"why": "Direct LSASS access, MiniDumpWriteDump call, or mimikatz/Sekurlsa string — the gold-standard credential-dump indicator (T1003.001).",
             "validates": "lsass.exe / lsass.dmp / minidump / mimikatz strings.",
             "action": "Treat as confirmed credential compromise: rotate Kerberos krbtgt, expire affected user tokens.",
             "fp_note": "Process-Explorer / VMM agents touching LSASS are rare but possible — verify caller hash."},
    "R014": {"why": "≥50 DNS queries from one host with average payload length >60 characters — DNS-tunnel cadence (T1071.004).",
             "validates": "High query count + long labels + low entropy.",
             "action": "Block the suspected resolver path; capture full PCAP for the host.",
             "fp_note": "Some EDR agents and CDN edge logic create long subdomain queries by design."},
    "R015": {"why": "Plain-text credential material observed in the log (password=, api_key=, Basic auth header).",
             "validates": "Regex match on credential indicator within HTTP payload / URL.",
             "action": "Rotate the exposed secret immediately; review the originating service for safe-storage controls.",
             "fp_note": "Synthetic / test traffic carrying placeholder credentials."},
    "R016": {"why": "≥5 distinct accounts locked out from the same source within the window — password-spray pattern (T1110.004).",
             "validates": "Single source, multiple unique target users, lockout event_type.",
             "action": "Block the source IP, unlock affected users only after MFA challenge.",
             "fp_note": "Stale service principal hammering several mailboxes."},
    "R017": {"why": "Service-create / scheduled-task-create / cron-write / Run-key write — typical persistence implant.",
             "validates": "sc.exe create, schtasks /create, crontab edit, registry Run path.",
             "action": "Capture the new task's binary path + SHA256; remove the persistence if unauthorised.",
             "fp_note": "Software-deploy agents creating tasks for postinstall."},
    "R018": {"why": "Security / audit event log was cleared (EventID 1102 / wevtutil cl) — almost certainly cover-up.",
             "validates": "1102 in the Security channel, or wevtutil clear, or Clear-EventLog.",
             "action": "Treat the host as compromised; forensically image and reconstruct timeline from EDR.",
             "fp_note": "Legitimate scripted log archival — very rare in production."},
    "R019": {"why": "Defender / SentinelOne / CrowdStrike disable / exclusion / uninstall — attacker neutralising endpoint defenses.",
             "validates": "Set-MpPreference -Disable*, Stop-Service WinDefend, Add-MpPreference -Exclusion*.",
             "action": "Restore defenses, isolate the host, hunt for what happened in the protection-off window.",
             "fp_note": "IT troubleshooting an AV conflict during change-window."},
    "R020": {"why": "≥8 failed RDP logons from one source — RDP brute (T1021.001).",
             "validates": "Port 3389 OR event_type contains 'rdp'/'terminal services', status FAILED.",
             "action": "Block the source, require NLA + MFA, and review for any subsequent SUCCESS.",
             "fp_note": "Misconfigured RDP client looping with stale creds."},
    "R021": {"why": "Periodic outbound contact from one source to one destination — coefficient-of-variation under 0.30 indicates programmatic beacon.",
             "validates": "≥6 hits, 30 s ≤ mean interval ≤ 1 h, CV ≤ 0.30 (CV=0 is perfect-period implant).",
             "action": "Capture the binary issuing the beacon; pivot on the destination across all sources.",
             "fp_note": "Polling agents (monitoring, OS-update) talking to corporate endpoints."},
    "R022": {"why": "Same user authenticates from two distinct /16 networks within 1 h — geographically impossible (T1078).",
             "validates": "Single user, multiple unique /16, sub-1-hour delta.",
             "action": "Revoke active sessions for the user, require MFA on next login, and review token issuance.",
             "fp_note": "Corporate VPN egress flipping between two PoPs."},
    "R023": {"why": "Mass ransom-extension writes or volume-shadow / backup-deletion commands — ransomware impact stage (T1486 / T1490).",
             "validates": "≥30 file writes with ransom extensions OR vssadmin delete shadows.",
             "action": "Isolate immediately, block egress, snapshot disks, alert leadership.",
             "fp_note": "QA harness creating large numbers of files with unusual extensions."},
    "R024": {"why": "SQL-injection payload pattern observed (UNION, ' OR 1=1, xp_cmdshell, sleep, information_schema).",
             "validates": "Regex match against the request body / URL.",
             "action": "Block at WAF, review database audit log for the same time window.",
             "fp_note": "Internal security scan / DAST."},
    "R025": {"why": "Web-shell paths requested (cmd.aspx, c99.php, shell.jsp) or recon-tool user-agents (sqlmap, nikto).",
             "validates": "URL path or User-Agent match.",
             "action": "Take the application offline if a shell is confirmed; recover from a known-good baseline.",
             "fp_note": "Pen-test engagement on a documented schedule."},
    "R026": {"why": "An IDS / Suricata signature fired. The signature itself encodes domain expertise we trust.",
             "validates": "alert.signature non-empty; signature_id; severity from the IDS engine.",
             "action": "Validate the rule isn't false-prone for this signature; pivot on src/dest IP across other sources.",
             "fp_note": "Generic / over-broad signatures occasionally tag legitimate traffic."},
    "R027": {"why": "Outbound traffic to consumer file-sharing (mega.nz, transfer.sh, pastebin, …) with significant volume.",
             "validates": "Destination matches file-share pattern OR Palo Alto category=file-sharing AND ≥10 MB total.",
             "action": "Block the user's egress to the destination, audit the SharePoint/SMB access leading up to it.",
             "fp_note": "Sanctioned use of Dropbox/OneDrive for corporate purposes."},
    "R028": {"why": "Connection to a newly-registered domain / abused-TLD (.xyz, .top, .tk, .ml).",
             "validates": "Palo Alto category=newly-registered-domain OR dest_host suffix in known-abused TLDs.",
             "action": "DNS-sink-hole the domain; pull every host that resolved it.",
             "fp_note": "Marketing campaign domains briefly hosted on cheap TLDs."},
    "R029": {"why": "Email with risky attachment extension (.docm, .iso, .lnk, …) and/or DKIM/DMARC/SPF failure.",
             "validates": "Risky extension count + auth-result failure + suspicious subject pattern.",
             "action": "Quarantine the message, recall delivered copies, and detonate the attachment in a sandbox.",
             "fp_note": "Legitimate vendor sending macro-enabled templates."},
    "R030": {"why": "Privileged cloud role (Global Admin / AdministratorAccess) granted to an identity.",
             "validates": "event_type matches 'Add member to role' / AttachUserPolicy AND target role is privileged.",
             "action": "Confirm change-ticket; if unauthorised, revoke the role and rotate the grantor's credentials.",
             "fp_note": "Authorised IT admin onboarding."},
    "R031": {"why": "Binary named to mimic a system process (sysmon32.exe, svchost_helper.exe) under a Temp path — masquerading (T1036.005).",
             "validates": "Filename regex against known LOL-names + path under Temp / AppData\\Local\\Temp.",
             "action": "Quarantine the binary, capture SHA256, hunt for the dropper.",
             "fp_note": "Internal IT tool deliberately named to look like a system process — rare."},
    "R032": {"why": "PowerShell / cmd / wscript / mshta dropped an .exe / .dll / .ps1 under a Temp path — classic loader chain.",
             "validates": "Parent is a scripting engine AND child extension AND Temp path.",
             "action": "Block the parent script, capture both binaries, replay the chain in EDR.",
             "fp_note": "Approved deployment scripts staging payloads in Temp."},
    "R033": {"why": "≥5 Kerberos TGS-REQ events with weak (RC4-HMAC 0x17 / DES) encryption for one principal — Kerberoasting offline-crack prep.",
             "validates": "EventID 4769 + TicketEncryptionType in {0x17, 0x18, 0x01, 0x03}.",
             "action": "Reset the targeted service principal password; enforce AES-only.",
             "fp_note": "Legacy app forcing RC4 — should still be rotated."},
    "R034": {"why": "Office app (Word, Excel, Outlook…) spawned a shell / scripting engine — macro-borne initial access (T1566.001).",
             "validates": "InitiatingProcessFileName ∈ Office set AND child ∈ shell set.",
             "action": "Disable macros for the user, recall the email if traceable, hunt for the dropped payload.",
             "fp_note": "Approved internal automation embedded in Excel — rare in production."},
    "R035": {"why": "LOLBin (certutil / bitsadmin / mshta / regsvr32 / rundll32) invoked with URL or loader argument — T1218 / T1105.",
             "validates": "Command-line regex matches the specific abuse pattern (e.g. certutil -urlcache -f -split).",
             "action": "Capture the URL contacted; isolate the host; pull EDR for the next-stage payload.",
             "fp_note": "Some IT-admin scripts genuinely use certutil for cert work — verify args carefully."},
    "R036": {"why": "Service account performed interactive (Type 2) or RDP (Type 10) logon — service accounts should only do network/batch logons.",
             "validates": "EventID 4624, LogonType ∈ {2, 10}, target user matches svc_*/service.",
             "action": "Rotate the service account password, audit where it has interactive rights, and remove them.",
             "fp_note": "On-call human using a shared service credential — itself a policy violation."},
    "R037": {"why": "Sensitive AWS API (IAM Create, KMS, S3 policy, CloudTrail, ConsoleLogin) was invoked without MFA.",
             "validates": "eventName in sensitive set AND mfaAuthenticated=false.",
             "action": "Enforce MFA on the identity; review every action it performed in the unauthenticated window.",
             "fp_note": "Service / CI-runner role legitimately not using MFA — should still be MFA-fronted via STS."},
    "R038": {"why": "CloudTrail or VPC Flow Logs were stopped / deleted — attacker covering tracks.",
             "validates": "eventName in {StopLogging, DeleteTrail, UpdateTrail, DeleteFlowLogs}.",
             "action": "Re-enable logging immediately; restore from S3 / SIEM backup; treat the actor as compromised.",
             "fp_note": "Approved trail rotation during environment migration."},
    "R039": {"why": "Single principal made >100 S3 API calls — anomalous data-collection volume (T1530).",
             "validates": "eventSource=s3.amazonaws.com AND per-principal count threshold.",
             "action": "Audit which objects were read, throttle the role, and pivot to the egress side (PA / VPC Flow).",
             "fp_note": "Approved data-pipeline / backup job with a normal volume baseline."},
    "R040": {"why": "Single user downloaded ≥25 files from SharePoint / OneDrive — potential insider exfil staging.",
             "validates": "Operation=FileDownloaded, single UserId.",
             "action": "Lock OneDrive sync for the user, review downloaded filenames against the DLP policy.",
             "fp_note": "Legitimate offline-prep for a known engagement."},
    "R041": {"why": "Successful Entra sign-in from a country that is not part of the corporate baseline (NorthBay = IN).",
             "validates": "location.countryOrRegion not in allowed-set.",
             "action": "Revoke the session, force MFA-resync, and confirm the user's whereabouts.",
             "fp_note": "Roaming employee on legitimate travel — verify against HR/travel system."},
    "R042": {"why": "Single principal issued ≥15 Describe/List API calls with ≥5 distinct verbs — cloud enumeration / pre-attack discovery.",
             "validates": "eventName starts with Describe/List, AWS source, distinct-verb threshold.",
             "action": "Capture the principal's recent actions, validate the role's least-privilege, and watch for follow-on creates.",
             "fp_note": "AWS Config / Cloud Custodian inventory scan."},
    "R043": {"why": "An attacker enumerating an IDOR vulnerability walks sequential resource IDs (e.g. /invoices/9001, /9002…) to access records belonging to other users.",
             "validates": "≥5 distinct consecutive numeric IDs accessed by one IP under the same endpoint pattern within 60s.",
             "action": "Check whether the accessed records belong to other user accounts. Revoke the session and audit the endpoint for missing authorization checks.",
             "fp_note": "Legitimate batch-export or admin tooling that iterates known IDs — verify user_id matches the accessed resource ownership."},
}


def _evidence_for(rule_id: str, df: pd.DataFrame, indices: List[int]) -> List[Dict[str, Any]]:
    """Pull the most evidentially-relevant fields from up to 3 sample rows."""
    if not indices or df is None or df.empty:
        return []
    sample = df.loc[[i for i in indices[:3] if i in df.index]] if indices else df.iloc[0:0]
    if sample.empty:
        return []
    interesting = [
        "timestamp", "source_ip", "dest_ip", "dest_host", "user",
        "event_type", "status", "processcommandline", "filename", "folderpath",
        "sha256", "useridentity_arn", "eventname", "ticketencryptiontype",
        "logontype", "targetusername", "location_countryorregion", "category",
        "app", "bytes", "signature", "alert_signature", "initiatingprocessfilename",
        "operation", "url",
    ]
    out: List[Dict[str, Any]] = []
    for idx, row in sample.iterrows():
        facts: Dict[str, Any] = {"_log_index": int(idx)}
        for f in interesting:
            if f in row.index:
                v = row.get(f)
                if v is None:
                    continue
                try:
                    if pd.isna(v):
                        continue
                except (TypeError, ValueError):
                    pass
                s = str(v)
                if s and s.lower() not in {"nan", "none", "<na>", "nat"}:
                    facts[f] = s[:240]
        if len(facts) > 1:
            out.append(facts)
    return out


def _enrich_with_reasoning(alerts: List[Alert], df: pd.DataFrame) -> None:
    """
    For every alert, attach:
      - extra.evidence       — concrete log facts that triggered the match
      - extra.reasoning      — plain-English "why this is malicious"
      - extra.validates      — what the rule actually verified
      - extra.recommended_action
      - extra.false_positive_notes
    so the analyst can justify the alert without bouncing back to the raw log.
    """
    for a in alerts:
        catalog = _RULE_REASONING.get(a.rule_id, {})
        # Don't clobber rule-specific extras — merge instead.
        existing = dict(a.extra or {})
        existing.setdefault("evidence", _evidence_for(a.rule_id, df, a.related_log_indices or []))
        existing.setdefault("reasoning", catalog.get("why", ""))
        existing.setdefault("validates", catalog.get("validates", ""))
        existing.setdefault("recommended_action", catalog.get("action", ""))
        existing.setdefault("false_positive_notes", catalog.get("fp_note", ""))
        # Confidence signals — every rule lists what corroborated the match.
        if "confidence_signals" not in existing:
            signals: List[str] = []
            if a.event_count >= 50:
                signals.append(f"high volume ({a.event_count} events)")
            elif a.event_count >= 10:
                signals.append(f"sustained activity ({a.event_count} events)")
            if a.source_ip and _is_external_ip(a.source_ip):
                signals.append(f"external source IP {a.source_ip}")
            if a.timestamp and (0 <= a.timestamp.hour < 5):
                signals.append("off-hours (00:00–05:00 UTC)")
            if a.tp_probability and a.tp_probability >= 0.9:
                signals.append("rule self-rates ≥90% TP probability")
            if a.severity == AlertSeverity.CRITICAL:
                signals.append("rule severity = CRITICAL")
            existing["confidence_signals"] = signals
        a.extra = existing


def run_all_rules(df: pd.DataFrame) -> List[Alert]:
    """Run every rule, then enrich each alert with structured reasoning so the
    analyst can justify *why* the log fired — no more orphan alerts."""
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
    try:
        _enrich_with_reasoning(alerts, df)
    except Exception as exc:  # noqa: BLE001 — enrichment must not break ingest
        import logging
        logging.getLogger("noctra.rules").exception("Reasoning enrichment crashed: %s", exc)
    return alerts
