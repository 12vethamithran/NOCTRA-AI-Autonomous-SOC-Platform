/**
 * utils/reportBuilder.js
 * ======================
 * Client-side incident report generator.
 *
 * Works for ANY session (backend-backed OR client-only demo sessions) because
 * it never calls the API — it renders directly from the in-memory session
 * object. Opens a styled, print-ready report in a new window and triggers the
 * browser print dialog (Save as PDF).
 *
 * Two distinct report profiles:
 *   - L1  → concise operational shift report (triage & response focused)
 *   - L2  → full forensic threat report (deep analysis, IOCs, kill-chain, hunts)
 */

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
const KILL_CHAIN = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

// ── Field normalisers (demo + backend shapes differ) ─────────────────────────
const tech    = (a) => a.mitre_techniques?.[0] || a.mitre_technique || '—'
const tactic  = (a) => a.mitre_tactics?.[0]   || a.mitre_tactic   || '—'
const prob    = (a) => a.tp_probability != null ? a.tp_probability
                     : a.ai_score != null ? a.ai_score / 100 : null
const aiText  = (a) => a.ai_rationale || a.ai_explanation || ''
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))

function computeMetrics(session) {
  const alerts   = session?.alerts   ?? []
  const verdicts = session?.verdicts ?? {}
  const tps = alerts.filter(a => verdicts[a.alert_id]?.decision === 'TP')
  const fps = alerts.filter(a => verdicts[a.alert_id]?.decision === 'FP')
  const pending = alerts.filter(a => !verdicts[a.alert_id])
  const coverage = alerts.length ? Math.round(((tps.length + fps.length) / alerts.length) * 100) : 0
  const precision = (tps.length + fps.length) ? Math.round((tps.length / (tps.length + fps.length)) * 100) : null

  const threatScore = alerts.length
    ? Math.min(100, Math.round(
        (alerts.reduce((s, a) => s + (SEV_RANK[a.severity] || 1) * (prob(a) ?? 0.5), 0) /
        (alerts.length * 4)) * 100))
    : 0

  const sevCounts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].reduce((acc, s) => {
    acc[s] = alerts.filter(a => a.severity === s).length; return acc
  }, {})

  const tacticCounts = alerts.reduce((acc, a) => {
    const t = tactic(a); if (t && t !== '—') acc[t] = (acc[t] || 0) + 1; return acc
  }, {})
  const chain = KILL_CHAIN.map(t => ({ tactic: t, count: tacticCounts[t] || 0 }))
                          .filter(c => c.count > 0)

  const ipMap = {}
  alerts.forEach(a => {
    if (!a.source_ip) return
    const e = ipMap[a.source_ip] || (ipMap[a.source_ip] = { ip: a.source_ip, count: 0, maxSev: 'LOW', tp: 0 })
    e.count++
    if ((SEV_RANK[a.severity] || 0) > (SEV_RANK[e.maxSev] || 0)) e.maxSev = a.severity
    if (verdicts[a.alert_id]?.decision === 'TP') e.tp++
  })
  const topIPs = Object.values(ipMap).sort((a, b) => b.count - a.count).slice(0, 8)

  const ips = new Set(), users = new Set(), techniques = new Set()
  alerts.forEach(a => {
    if (a.source_ip) ips.add(a.source_ip)
    if (a.dest_ip)   ips.add(a.dest_ip)
    if (a.user) String(a.user).split(',').forEach(u => u.trim() && users.add(u.trim()))
    if (tech(a) !== '—') techniques.add(tech(a))
  })

  return {
    alerts, verdicts, tps, fps, pending, coverage, precision, threatScore,
    sevCounts, chain, topIPs,
    iocs: { ips: [...ips], users: [...users], techniques: [...techniques] },
    riskLabel: threatScore >= 66 ? 'SEVERE' : threatScore >= 33 ? 'ELEVATED' : 'GUARDED',
  }
}

function recommendations(tps) {
  const ids = new Set(tps.map(t => t.rule_id))
  const r = []
  if (ids.has('R001')) r.push('Enforce account lockout after 5 failed attempts and require MFA on all administrative accounts.')
  if (ids.has('R002')) r.push('Restrict perimeter exposure to only the network ports actively in use; deploy port-scan detection at the firewall.')
  if (ids.has('R003') || ids.has('R004')) r.push('Audit privileged-access policy and enable session recording for all administrator logons.')
  if (ids.has('R005')) r.push('Tighten egress DLP policy on impacted source hosts and alert on anomalous outbound volume.')
  if (ids.has('R009')) r.push('Subscribe perimeter firewalls to an updated threat-intelligence feed and auto-block known-malicious IPs.')
  if (tps.length) r.push('Isolate all hosts associated with confirmed True Positives and rotate any potentially exposed credentials.')
  if (!r.length) r.push('No specific remediation required beyond standard security hygiene. Continue monitoring.')
  return r
}

// ── Shared CSS for the printable document ────────────────────────────────────
const CSS = `
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Inter,Arial,sans-serif;color:#0f172a;background:#fff;font-size:12px;line-height:1.5}
  .wrap{max-width:900px;margin:0 auto;padding:36px 44px}
  .bar{height:6px;background:linear-gradient(90deg,#9f1239,#e11d48,#f43f5e);border-radius:3px;margin-bottom:22px}
  h1{font-size:24px;color:#0f172a;letter-spacing:-.4px}
  .sub{color:#64748b;font-size:11px;margin-top:3px}
  h2{font-size:15px;color:#9f1239;border-bottom:2px solid #fecdd3;padding-bottom:5px;margin:26px 0 12px;text-transform:uppercase;letter-spacing:.5px}
  h3{font-size:13px;color:#0f172a;margin:14px 0 6px}
  p{margin:6px 0}
  .badge{display:inline-block;padding:3px 12px;border-radius:99px;font-weight:700;font-size:11px;color:#fff}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
  .tile{border:1px solid #e2e8f0;border-radius:10px;padding:12px;background:#f8fafc}
  .tile .k{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#64748b}
  .tile .v{font-size:22px;font-weight:800;margin-top:4px}
  table{width:100%;border-collapse:collapse;margin:10px 0;font-size:11px}
  th{background:#9f1239;color:#fff;text-align:left;padding:7px 9px;font-size:10px;text-transform:uppercase;letter-spacing:.4px}
  td{padding:7px 9px;border-bottom:1px solid #e2e8f0;vertical-align:top}
  tr:nth-child(even) td{background:#f8fafc}
  .inc{border:1px solid #e2e8f0;border-left:4px solid #e11d48;border-radius:8px;padding:14px;margin:12px 0;background:#fff;page-break-inside:avoid}
  .inc .meta{display:grid;grid-template-columns:repeat(2,1fr);gap:4px 18px;font-size:11px;margin:8px 0}
  .inc .meta b{color:#64748b;font-weight:600}
  .ai{background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:9px;font-size:11px;margin-top:8px}
  pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;font-size:10px;overflow-x:auto;white-space:pre-wrap;margin-top:8px}
  .chain{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
  .phase{border:1px solid #fecdd3;background:#fff1f2;border-radius:8px;padding:8px 10px;text-align:center;min-width:90px}
  .phase .t{font-size:9px;font-weight:700;color:#9f1239}
  .phase .c{font-size:16px;font-weight:800;color:#0f172a}
  ol{margin:8px 0 8px 20px}li{margin:5px 0}
  .foot{margin-top:34px;border-top:1px solid #e2e8f0;padding-top:14px;color:#94a3b8;font-size:10px;display:flex;justify-content:space-between}
  .sign{margin-top:30px;display:flex;gap:60px}
  .sign div{flex:1;border-top:1px solid #475569;padding-top:6px;font-size:11px;color:#475569}
  .classif{text-align:center;font-weight:800;letter-spacing:3px;color:#9f1239;font-size:11px;margin-bottom:6px}
  @media print{.noprint{display:none}body{font-size:11px}.wrap{padding:0}}
`

const sevColor = (s) => ({ CRITICAL: '#b91c1c', HIGH: '#c2410c', MEDIUM: '#a16207', LOW: '#475569' }[s] || '#475569')

function header(role, analyst, session) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
  return `
  <div class="classif">CONFIDENTIAL // SOC ${role} ANALYST REPORT</div>
  <div class="bar"></div>
  <div style="display:flex;justify-content:space-between;align-items:flex-end">
    <div>
      <h1>NOCTRA AI</h1>
      <div class="sub">${role === 'L1' ? 'Tier-1 Operational Shift Report' : 'Tier-2 Forensic Threat Analysis Report'}</div>
    </div>
    <div style="text-align:right;font-size:11px;color:#64748b">
      <div><b>Generated:</b> ${esc(now)}</div>
      <div><b>Analyst:</b> ${esc(analyst)} (${role})</div>
      <div><b>Session:</b> ${esc(session.session_id)}</div>
    </div>
  </div>`
}

function sessionTable(session, m) {
  return `<h2>Session Overview</h2><table>
    <tr><th>Source File</th><td>${esc(session.source_filename || session.filename || '—')}</td>
        <th>Format</th><td>${esc(session.parsed_format || '—')}</td></tr>
    <tr><th>Events Parsed</th><td>${(session.event_count ?? 0).toLocaleString()}</td>
        <th>Alerts Detected</th><td>${m.alerts.length}</td></tr>
    <tr><th>True Positives</th><td>${m.tps.length}</td>
        <th>False Positives</th><td>${m.fps.length}</td></tr>
    <tr><th>Pending Review</th><td>${m.pending.length}</td>
        <th>Triage Coverage</th><td>${m.coverage}%</td></tr>
  </table>`
}

// ── L1: concise operational report ───────────────────────────────────────────
function buildL1(session, analyst) {
  const m = computeMetrics(session)
  const crit = m.pending.filter(a => a.severity === 'CRITICAL').length
  return `
  ${header('L1', analyst, session)}
  ${sessionTable(session, m)}

  <h2>Shift Summary</h2>
  <div class="grid">
    <div class="tile"><div class="k">Queue Depth</div><div class="v" style="color:#e11d48">${m.pending.length}</div></div>
    <div class="tile"><div class="k">Resolved</div><div class="v" style="color:#0f172a">${m.tps.length + m.fps.length}</div></div>
    <div class="tile"><div class="k">Confirmed Threats</div><div class="v" style="color:#b91c1c">${m.tps.length}</div></div>
    <div class="tile"><div class="k">Coverage</div><div class="v" style="color:${m.coverage === 100 ? '#16a34a' : '#e11d48'}">${m.coverage}%</div></div>
  </div>
  <p>${m.alerts.length} alert(s) processed this shift. ${m.tps.length} confirmed True Positive(s) escalated,
  ${m.fps.length} dismissed as False Positive(s), <b>${m.pending.length} still pending</b>
  ${crit ? `including <b style="color:#b91c1c">${crit} CRITICAL</b> awaiting immediate triage` : ''}.</p>

  <h2>Confirmed Incidents — Escalation List</h2>
  ${m.tps.length ? `<table>
    <tr><th>Rule</th><th>Name</th><th>Severity</th><th>Source IP</th><th>MITRE</th><th>Status</th></tr>
    ${m.tps.map(a => `<tr>
      <td>${esc(a.rule_id)}</td><td>${esc(a.rule_name)}</td>
      <td><span class="badge" style="background:${sevColor(a.severity)}">${esc(a.severity)}</span></td>
      <td>${esc(a.source_ip || '—')}</td><td>${esc(tech(a))}</td>
      <td><b style="color:#b91c1c">ESCALATE → IR</b></td></tr>`).join('')}
  </table>` : '<p>No confirmed incidents this shift. Queue clean.</p>'}

  <h2>Action Items</h2>
  <ol>
    ${crit ? `<li><b>Priority:</b> ${crit} CRITICAL alert(s) still pending — triage before end of shift.</li>` : ''}
    ${m.tps.length ? `<li>Hand off ${m.tps.length} confirmed incident(s) to Tier-2 / Incident Response.</li>` : ''}
    ${m.pending.length ? `<li>Complete triage on ${m.pending.length} remaining queued alert(s).</li>` : ''}
    <li>Update shift handover notes and confirm coverage target met (${m.coverage}%).</li>
  </ol>

  <div class="sign"><div>Analyst Signature — ${esc(analyst)}</div><div>Shift Lead Review</div></div>
  <div class="foot"><span>NOCTRA AI · Storageless SOC Platform</span><span>L1 Operational Report</span></div>`
}

// ── L2: full forensic report ─────────────────────────────────────────────────
function buildL2(session, analyst) {
  const m = computeMetrics(session)
  return `
  ${header('L2', analyst, session)}
  ${sessionTable(session, m)}

  <h2>Executive Summary</h2>
  <p>
    <span class="badge" style="background:${m.threatScore >= 66 ? '#b91c1c' : m.threatScore >= 33 ? '#c2410c' : '#475569'}">
    THREAT POSTURE: ${m.riskLabel} · ${m.threatScore}/100</span>
  </p>
  <p>This session produced <b>${m.alerts.length}</b> alert(s) across
  <b>${(session.event_count ?? 0).toLocaleString()}</b> log events.
  ${m.tps.length} confirmed True Positive(s), ${m.fps.length} False Positive(s),
  ${m.pending.length} pending. Detection precision: <b>${m.precision != null ? m.precision + '%' : 'N/A'}</b>.
  The composite threat score (severity weighted by AI confidence) is <b>${m.threatScore}/100 (${m.riskLabel})</b>.
  ${m.tps.length ? `Primary confirmed threat: <b>${esc(m.tps.slice().sort((a,b)=>(SEV_RANK[b.severity]||0)-(SEV_RANK[a.severity]||0))[0].rule_name)}</b>.` : ''}</p>

  <div class="grid">
    <div class="tile"><div class="k">Threat Score</div><div class="v" style="color:#b91c1c">${m.threatScore}</div></div>
    <div class="tile"><div class="k">CRITICAL</div><div class="v" style="color:#b91c1c">${m.sevCounts.CRITICAL}</div></div>
    <div class="tile"><div class="k">HIGH</div><div class="v" style="color:#c2410c">${m.sevCounts.HIGH}</div></div>
    <div class="tile"><div class="k">Kill-Chain Phases</div><div class="v" style="color:#0f172a">${m.chain.length}/12</div></div>
  </div>

  <h2>Attack Kill-Chain Progression</h2>
  ${m.chain.length ? `<div class="chain">
    ${m.chain.map(c => `<div class="phase"><div class="t">${esc(c.tactic)}</div><div class="c">${c.count}</div></div>`).join('')}
  </div><p>The adversary activity spans <b>${m.chain.length}</b> distinct ATT&CK tactic(s).
  ${m.chain.length >= 4 ? 'This multi-stage progression is consistent with a coordinated, hands-on-keyboard campaign rather than isolated noise.' : 'Limited progression — likely opportunistic or early-stage activity.'}</p>`
  : '<p>No MITRE tactic mapping available for this session.</p>'}

  <h2>Confirmed Incidents — Forensic Detail</h2>
  ${m.tps.length ? m.tps.map((a, i) => {
    const p = prob(a)
    return `<div class="inc">
      <h3>#${i + 1} · ${esc(a.rule_id)} — ${esc(a.rule_name)}
        <span class="badge" style="background:${sevColor(a.severity)};margin-left:8px">${esc(a.severity)}</span></h3>
      <p>${esc(a.description || '')}</p>
      <div class="meta">
        <div><b>Source IP:</b> ${esc(a.source_ip || '—')}</div>
        <div><b>Destination:</b> ${esc(a.dest_ip || '—')}</div>
        <div><b>User:</b> ${esc(a.user || '—')}</div>
        <div><b>AI Confidence:</b> ${p != null ? Math.round(p * 100) + '%' : '—'}</div>
        <div><b>MITRE Technique:</b> ${esc(tech(a))}</div>
        <div><b>MITRE Tactic:</b> ${esc(tactic(a))}</div>
        <div><b>Event Count:</b> ${esc(a.event_count ?? '—')}</div>
        <div><b>Timestamp:</b> ${a.timestamp ? esc(new Date(a.timestamp).toUTCString()) : '—'}</div>
      </div>
      ${aiText(a) ? `<div class="ai"><b>AI Assessment:</b> ${esc(aiText(a))}</div>` : ''}
      ${m.verdicts[a.alert_id]?.notes ? `<p><b>Analyst Notes:</b> <i>"${esc(m.verdicts[a.alert_id].notes)}"</i></p>` : ''}
      ${a.raw_log ? `<pre>${esc(String(a.raw_log).replace(/\\n/g, '\n'))}</pre>` : ''}
    </div>`
  }).join('') : '<p>No confirmed incidents. All alerts were dismissed or remain pending.</p>'}

  <h2>Indicators of Compromise</h2>
  <table>
    <tr><th>Type</th><th>Count</th><th>Values</th></tr>
    <tr><td>IP Addresses</td><td>${m.iocs.ips.length}</td><td>${esc(m.iocs.ips.join(', ') || '—')}</td></tr>
    <tr><td>User Accounts</td><td>${m.iocs.users.length}</td><td>${esc(m.iocs.users.join(', ') || '—')}</td></tr>
    <tr><td>MITRE Techniques</td><td>${m.iocs.techniques.length}</td><td>${esc(m.iocs.techniques.join(', ') || '—')}</td></tr>
  </table>

  <h2>Top Source IPs (Talkers)</h2>
  ${m.topIPs.length ? `<table>
    <tr><th>IP Address</th><th>Alerts</th><th>Max Severity</th><th>Confirmed TP</th></tr>
    ${m.topIPs.map(t => `<tr><td>${esc(t.ip)}</td><td>${t.count}</td>
      <td><span class="badge" style="background:${sevColor(t.maxSev)}">${esc(t.maxSev)}</span></td>
      <td>${t.tp || 0}</td></tr>`).join('')}
  </table>` : '<p>No source IP data extracted.</p>'}

  <h2>Threat-Hunt Hypotheses</h2>
  <ol>
    ${m.sevCounts.CRITICAL > 0 ? `<li>Pivot on the ${m.sevCounts.CRITICAL} CRITICAL alert(s): correlate source IPs across the full timeline for lateral movement and privilege escalation chains.</li>` : ''}
    ${m.chain.length >= 4 ? `<li>Multi-stage attack detected (${m.chain.length} phases): reconstruct the end-to-end attack path and identify the initial access vector.</li>` : ''}
    ${m.topIPs[0] && m.topIPs[0].count >= 3 ? `<li>Repeat offender ${esc(m.topIPs[0].ip)} (${m.topIPs[0].count} alerts): hunt for C2 beaconing and persistence mechanisms on associated hosts.</li>` : ''}
    <li>Sweep the environment for the ${m.iocs.techniques.length} observed ATT&CK technique(s) beyond this session's log window.</li>
  </ol>

  <h2>Recommendations</h2>
  <ol>${recommendations(m.tps).map(r => `<li>${esc(r)}</li>`).join('')}</ol>

  <div class="sign"><div>L2 Analyst — ${esc(analyst)}</div><div>SOC Manager Approval</div></div>
  <div class="foot"><span>NOCTRA AI · Storageless SOC Platform · CONFIDENTIAL</span><span>L2 Forensic Report</span></div>`
}

/**
 * Generate and open the printable report.
 * @param {object} session  the in-memory session object
 * @param {'L1'|'L2'} role
 * @param {string} analyst  analyst name for signoff
 */
export function generateReport(session, role = 'L2', analyst = 'SOC Analyst') {
  if (!session) throw new Error('No active session')
  const body = role === 'L1' ? buildL1(session, analyst) : buildL2(session, analyst)
  const html = `<!doctype html><html><head><meta charset="utf-8">
    <title>NOCTRA AI ${role} Report — ${esc(session.session_id)}</title>
    <style>${CSS}</style></head>
    <body><div class="wrap">
      <div class="noprint" style="text-align:right;margin-bottom:10px">
        <button onclick="window.print()" style="background:#e11d48;color:#fff;border:0;padding:9px 18px;border-radius:8px;font-weight:700;cursor:pointer">⎙ Save as PDF / Print</button>
      </div>
      ${body}
    </div>
    <script>window.onload=function(){setTimeout(function(){window.print()},400)}</script>
    </body></html>`

  const w = window.open('', '_blank')
  if (!w) throw new Error('Popup blocked — allow popups to download the report')
  w.document.open()
  w.document.write(html)
  w.document.close()
}
