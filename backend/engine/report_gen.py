"""
engine/report_gen.py
====================
ReportLab-based PDF incident report.

Layout:
    [Header bar]
      Noctra AI
      INCIDENT REPORT - <date>

    [Session block]
      Session ID, Generated At, Analyst, Source file, Format, Event count

    [Executive summary]
      N alerts detected across M events.
      X True Positives. Y False Positives. Z Pending.
      Primary threat sentence.

    [Confirmed incidents]
      One table per TP alert (rule_id, severity, source_ip, user, MITRE).
      Description + analyst notes underneath.

    [False positives (compact)]

    [Indicators of compromise]
      IPs / Users / Ports — global, dedupliclated.

    [Recommendations]
      Boilerplate but rule-aware.

PDF is written to an in-memory BytesIO and streamed back.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from session.store import SessionData


_SEVERITY_COLOUR = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#a16207"),
    "LOW": colors.HexColor("#374151"),
}


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=18, leading=22,
                                textColor=colors.HexColor("#0f172a"), spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"], fontSize=10,
                                   textColor=colors.HexColor("#475569"), spaceAfter=12),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, leading=16,
                             textColor=colors.HexColor("#0f172a"), spaceBefore=10, spaceAfter=6),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=10, leading=13),
        "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8,
                                textColor=colors.HexColor("#475569")),
    }


def _kv_table(data: List[List[str]]) -> Table:
    t = Table(data, colWidths=[4.0 * cm, 13.0 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _alerts_by_verdict(sess: SessionData):
    tps, fps, pending = [], [], []
    for alert in sess.alerts:
        v = sess.verdicts.get(alert["alert_id"])
        if not v:
            pending.append(alert)
        elif v["decision"] == "TP":
            tps.append((alert, v))
        elif v["decision"] == "FP":
            fps.append((alert, v))
    return tps, fps, pending


def _primary_threat_sentence(tps, alerts) -> str:
    if tps:
        worst = max(tps, key=lambda t: _sev_rank(t[0]["severity"]))[0]
        return (f"Primary confirmed threat: {worst['rule_name']} "
                f"({worst['severity']}) from {worst.get('source_ip') or 'unknown source'}.")
    if alerts:
        worst = max(alerts, key=lambda a: _sev_rank(a["severity"]))
        return (f"Highest-severity alert (not yet adjudicated): {worst['rule_name']} "
                f"({worst['severity']}).")
    return "No alerts were detected in this session."


def _sev_rank(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(s).upper(), 0)


def _collect_iocs(sess: SessionData) -> Dict[str, List[str]]:
    ips, users, ports = set(), set(), set()
    for a in sess.alerts:
        if a.get("source_ip"): ips.add(a["source_ip"])
        if a.get("dest_ip"): ips.add(a["dest_ip"])
        if a.get("user"):
            for u in str(a["user"]).split(","):
                u = u.strip()
                if u: users.add(u)
    df = sess.logs
    if df is not None and not df.empty:
        if "port" in df.columns:
            for p in df["port"].dropna().unique():
                try: ports.add(str(int(p)))
                except Exception: pass
    return {
        "ips": sorted(ips),
        "users": sorted(users),
        "ports": sorted(ports, key=lambda x: int(x) if x.isdigit() else 0),
    }


def _recommendations(tps) -> List[str]:
    """Rule-aware boilerplate, deduped."""
    recs: List[str] = []
    rule_ids = {t[0]["rule_id"] for t in tps}
    if "R001" in rule_ids:
        recs += [
            "Enforce account lockout after 5 failed attempts.",
            "Require MFA on every administrative account.",
        ]
    if "R002" in rule_ids:
        recs.append("Restrict perimeter exposure to only the ports actually in use.")
    if "R003" in rule_ids or "R004" in rule_ids:
        recs.append("Audit privileged-access policy and enable session recording for admins.")
    if "R005" in rule_ids:
        recs.append("Tighten egress DLP policy on the impacted source host.")
    if "R009" in rule_ids:
        recs.append("Subscribe perimeter firewalls to an updated threat-intel feed.")
    if not recs:
        recs.append("No specific remediation required beyond standard hygiene.")
    return recs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def build_pdf(sess: SessionData, analyst: str = "L2 Analyst") -> bytes:
    """Build the report and return it as bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.8 * cm, bottomMargin=1.8 * cm,
        title=f"Noctra AI Incident Report - {sess.session_id[:8]}",
    )
    styles = _styles()
    story = []

    # Header
    story.append(Paragraph("Noctra AI", styles["title"]))
    story.append(Paragraph(
        f"INCIDENT REPORT &mdash; generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["subtitle"],
    ))

    tps, fps, pending = _alerts_by_verdict(sess)

    # Session block
    story.append(Paragraph("Session", styles["h2"]))
    story.append(_kv_table([
        ["Session ID", sess.session_id],
        ["Analyst", analyst],
        ["Source file", sess.source_filename or "-"],
        ["Format", sess.parsed_format or "-"],
        ["Events parsed", str(sess.event_count)],
        ["Alerts detected", str(len(sess.alerts))],
        ["True Positives", str(len(tps))],
        ["False Positives", str(len(fps))],
        ["Pending", str(len(pending))],
    ]))
    story.append(Spacer(1, 8))

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(Paragraph(
        f"{len(sess.alerts)} alert(s) detected across {sess.event_count} log events. "
        f"{len(tps)} confirmed True Positive(s). "
        f"{len(fps)} False Positive(s). "
        f"{len(pending)} pending analyst review. "
        f"{_primary_threat_sentence(tps, sess.alerts)}",
        styles["body"],
    ))

    # Confirmed incidents
    if tps:
        story.append(Paragraph("Confirmed Incidents", styles["h2"]))
        for alert, verdict in tps:
            sev = str(alert["severity"]).upper()
            header = Paragraph(
                f"<b>{alert['rule_id']}</b> &mdash; {alert['rule_name']}  "
                f"<font color='{_SEVERITY_COLOUR.get(sev, colors.black).hexval()}'>"
                f"[{sev}]</font>",
                styles["body"],
            )
            story.append(header)
            story.append(_kv_table([
                ["Source IP", alert.get("source_ip") or "-"],
                ["Destination", alert.get("dest_ip") or "-"],
                ["User", alert.get("user") or "-"],
                ["MITRE", f"{alert.get('mitre_technique') or '-'} "
                          f"({alert.get('mitre_tactic') or '-'})"],
                ["TP probability", f"{alert.get('tp_probability')}" if alert.get("tp_probability") is not None else "-"],
                ["Events", str(alert.get("event_count") or 0)],
                ["Verdict notes", verdict.get("notes") or "-"],
            ]))
            story.append(Paragraph(alert["description"], styles["body"]))
            if alert.get("ai_explanation"):
                story.append(Paragraph(
                    f"<i>AI:</i> {alert['ai_explanation']}", styles["small"]))
            story.append(Spacer(1, 6))

    # False positives (compact)
    if fps:
        story.append(Paragraph("Dismissed (False Positives)", styles["h2"]))
        rows = [["Rule", "Description", "Reason"]]
        for a, v in fps:
            rows.append([a["rule_id"], a["description"][:80], v.get("fp_reason") or "-"])
        t = Table(rows, colWidths=[1.8 * cm, 11 * cm, 4 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t)

    # IOCs
    iocs = _collect_iocs(sess)
    story.append(Paragraph("Indicators of Compromise", styles["h2"]))
    story.append(_kv_table([
        ["IPs",   ", ".join(iocs["ips"])   or "-"],
        ["Users", ", ".join(iocs["users"]) or "-"],
        ["Ports", ", ".join(iocs["ports"]) or "-"],
    ]))

    # Recommendations
    story.append(Paragraph("Recommendations", styles["h2"]))
    for i, r in enumerate(_recommendations(tps), 1):
        story.append(Paragraph(f"{i}. {r}", styles["body"]))

    doc.build(story)
    return buf.getvalue()
