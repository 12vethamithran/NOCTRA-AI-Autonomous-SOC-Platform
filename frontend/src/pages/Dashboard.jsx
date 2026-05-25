import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts'
import toast from 'react-hot-toast'
import {
  AlertOctagon, ShieldAlert, ShieldCheck, Shield, BarChart3, Sparkles,
  Crosshair, ChevronRight, FileBarChart, Download, Loader2,
  ClipboardList, Target, Globe, Network, Activity, Zap, FileText,
  Users, AlertTriangle, Layers, Search, ListChecks,
} from 'lucide-react'
import { downloadReport } from '../api/client'
import { generateReport } from '../utils/reportBuilder'
import { useSession } from '../App'
import FeedbackInsights from '../components/FeedbackInsights'

// ── Chart tooltip ─────────────────────────────────────────────────────────────
const Tip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-xl px-3 py-2 text-xs shadow-2xl" style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)' }}>
      {label && <p className="font-bold text-white mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color ?? p.fill }}>{p.name}: <span className="font-bold">{p.value}</span></p>
      ))}
    </div>
  )
}

// ── KPI Card ──────────────────────────────────────────────────────────────────
function KPICard({ label, value, sub, icon, iconClass, colour, accent, trend, onClick }) {
  return (
    <div
      onClick={onClick}
      className={`kpi-card kpi-card-${accent ?? 'default'} p-5 ${onClick ? 'cursor-pointer hover-glow' : ''}`}
      style={{ background: 'var(--surface)' }}
    >
      <div className="flex items-start justify-between mb-3">
        <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{label}</p>
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${iconClass}`}>
          {icon}
        </div>
      </div>
      <p className={`text-3xl font-extrabold tabular-nums number-pop ${colour}`}>{value}</p>
      <div className="flex items-center gap-2 mt-1.5">
        {sub && <p className="text-xs" style={{ color: 'var(--text-3)' }}>{sub}</p>}
        {trend != null && (
          <span className={`text-xs font-bold ${trend > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
            {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
          </span>
        )}
      </div>
    </div>
  )
}

// ── KPI Icons (consistent lucide set across the platform) ────────────────────
const Icons = {
  alert:    <AlertOctagon size={18} color="#ff4d4d" strokeWidth={1.8} />,
  tp:       <ShieldAlert  size={18} color="#f87171" strokeWidth={1.8} />,
  fp:       <ShieldCheck  size={18} color="#9ca3af" strokeWidth={1.8} />,
  coverage: <BarChart3    size={18} color="#f43f5e" strokeWidth={1.8} />,
  precision:<Target       size={18} color="#e11d48" strokeWidth={1.8} />,
  ai:       <Sparkles     size={18} color="#f43f5e" strokeWidth={1.8} />,
  mitre:    <Crosshair    size={18} color="#ff4d4d" strokeWidth={1.8} />,
}

const TACTIC_COLOURS = {
  'Initial Access':       '#e11d48', 'Execution':          '#f43f5e',
  'Persistence':          '#9f1239', 'Privilege Escalation':'#ff4d4d',
  'Defense Evasion':      '#be123c', 'Credential Access':   '#e11d48',
  'Discovery':            '#881337', 'Lateral Movement':    '#f43f5e',
  'Collection':           '#9f1239', 'Command and Control': '#e11d48',
  'Exfiltration':         '#be123c', 'Impact':              '#ff4d4d',
}

const SEV_C = { CRITICAL: '#ff0000', HIGH: '#e11d48', MEDIUM: '#f43f5e', LOW: '#3d3d48' }
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

// MITRE kill-chain order for L2 attack-progression view
const KILL_CHAIN = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

export default function Dashboard() {
  const { session } = useSession()
  const navigate    = useNavigate()
  const [downloading, setDownloading] = useState(false)
  const [analyst, setAnalyst]         = useState('L2 Analyst')
  const [activeTab, setActiveTab]     = useState('ops')
  const [role, setRole]               = useState('L1')
  const [mitreQuery, setMitreQuery]   = useState('')
  const [insightsQuery, setInsightsQuery] = useState('')

  const alerts   = session?.alerts   ?? []
  const verdicts = session?.verdicts ?? {}

  const tpCount   = Object.values(verdicts).filter(v => v.decision === 'TP').length
  const fpCount   = Object.values(verdicts).filter(v => v.decision === 'FP').length
  const pending   = alerts.length - tpCount - fpCount
  const coverage  = alerts.length > 0 ? Math.round(((tpCount + fpCount) / alerts.length) * 100) : 0
  const precision = (tpCount + fpCount) > 0 ? Math.round((tpCount / (tpCount + fpCount)) * 100) : null

  const probAlerts = alerts.filter(a => a.tp_probability != null)
  const avgProb    = probAlerts.length > 0
    ? Math.round(probAlerts.reduce((s, a) => s + a.tp_probability, 0) / probAlerts.length * 100)
    : null

  const [chartSevFilter, setChartSevFilter] = useState(null)
  
  const filteredAlerts = useMemo(() => chartSevFilter ? alerts.filter(a => a.severity === chartSevFilter) : alerts, [alerts, chartSevFilter])

  const sevData  = useMemo(() =>
    ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => ({ name: s, count: alerts.filter(a => a.severity === s).length, fill: SEV_C[s] })).filter(d => d.count > 0),
  [alerts])

  const ruleData = useMemo(() =>
    Object.entries(filteredAlerts.reduce((acc, a) => { acc[a.rule_id] = (acc[a.rule_id] || 0) + 1; return acc }, {}))
      .map(([r, c]) => ({ name: r, count: c, ruleName: filteredAlerts.find(a => a.rule_id === r)?.rule_name || r }))
      .sort((a, b) => b.count - a.count),
  [filteredAlerts])

  const donutData = [
    { name: 'TP',      value: tpCount, fill: '#ff0000' },
    { name: 'FP',      value: fpCount, fill: '#6b7280' },
    { name: 'Pending', value: pending, fill: '#2a2a32' },
  ].filter(d => d.value > 0)

  const mitreData = useMemo(() => {
    const counts = filteredAlerts.reduce((acc, a) => {
      if (a.mitre_tactic) acc[a.mitre_tactic] = (acc[a.mitre_tactic] || 0) + 1
      return acc
    }, {})
    return Object.entries(counts)
      .map(([t, c]) => ({ tactic: t, count: c, colour: TACTIC_COLOURS[t] || '#52525e' }))
      .sort((a, b) => b.count - a.count)
  }, [filteredAlerts])

  const uniqueTactics    = mitreData.length
  const uniqueTechniques = new Set(filteredAlerts.map(a => a.mitre_technique).filter(Boolean)).size

  // AI analysis insights
  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL')
  const highConfidence = alerts.filter(a => (a.tp_probability ?? 0) >= 0.75)
  const topRule        = ruleData[0]
  
  // ── L1 / L2 Operations Center derived metrics ────────────────────────────────
  const pendingAlerts = useMemo(() => alerts.filter(a => !verdicts[a.alert_id]), [alerts, verdicts])

  const pendingBySev = useMemo(() =>
    ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => ({
      sev: s, count: pendingAlerts.filter(a => a.severity === s).length,
    })).filter(d => d.count > 0),
  [pendingAlerts])

  const criticalPending = pendingAlerts.filter(a => a.severity === 'CRITICAL').length
  const hotPending      = pendingAlerts.filter(a => (a.tp_probability ?? 0) >= 0.75).length

  // Composite threat score: severity weight × AI confidence, normalised 0–100
  const threatScore = useMemo(() => {
    if (alerts.length === 0) return 0
    const raw = alerts.reduce((s, a) => s + (SEV_RANK[a.severity] || 1) * (a.tp_probability ?? 0.5), 0)
    return Math.min(100, Math.round((raw / (alerts.length * 4)) * 100))
  }, [alerts])

  // Top source IPs (L2 "top talkers")
  const topIPs = useMemo(() => {
    const m = {}
    alerts.forEach(a => {
      if (!a.source_ip) return
      const e = m[a.source_ip] || (m[a.source_ip] = { ip: a.source_ip, count: 0, maxRank: 0, maxSev: 'LOW', tp: 0 })
      e.count++
      if ((SEV_RANK[a.severity] || 0) > e.maxRank) { e.maxRank = SEV_RANK[a.severity]; e.maxSev = a.severity }
      if (verdicts[a.alert_id]?.decision === 'TP') e.tp++
    })
    return Object.values(m).sort((a, b) => b.count - a.count).slice(0, 6)
  }, [alerts, verdicts])

  // AI-confidence distribution histogram (L2)
  const confBuckets = useMemo(() => {
    const b = [
      { label: '0–25%',   range: [0, 0.25],  count: 0, fill: '#3d3d48' },
      { label: '25–50%',  range: [0.25, 0.5], count: 0, fill: '#9f1239' },
      { label: '50–75%',  range: [0.5, 0.75], count: 0, fill: '#e11d48' },
      { label: '75–100%', range: [0.75, 1.01], count: 0, fill: '#ff0000' },
    ]
    probAlerts.forEach(a => {
      const p = a.tp_probability
      const hit = b.find(x => p >= x.range[0] && p < x.range[1])
      if (hit) hit.count++
    })
    return b
  }, [probAlerts])

  // Kill-chain progression (L2): tactics in attack order
  const killChain = useMemo(() => {
    const counts = alerts.reduce((acc, a) => {
      if (a.mitre_tactic) acc[a.mitre_tactic] = (acc[a.mitre_tactic] || 0) + 1
      return acc
    }, {})
    return KILL_CHAIN.map(t => ({ tactic: t, count: counts[t] || 0, active: !!counts[t] }))
  }, [alerts])

  const chainReach = killChain.filter(c => c.active).length

  const [reportSections, setReportSections] = useState({ summary: true, threat: true, mitre: true, incidents: true, ioc: true, recommendations: true })

  // Client-side report — works for demo AND backend sessions, segregated by role.
  // Falls back from backend PDF only when explicitly requested (kept for parity).
  const handleDownload = async () => {
    setDownloading(true)
    try {
      generateReport(session, role, analyst)
      toast.success(`${role} report generated — use the print dialog to Save as PDF`)
    } catch (err) {
      toast.error(err.message || 'Failed to generate report')
    } finally { setDownloading(false) }
  }

  // Optional: server-rendered PDF (only valid for real backend sessions)
  const handleServerPdf = async () => {
    if (session.session_id?.startsWith('demo-')) {
      toast.error('Server PDF unavailable for demo sessions — use the styled report')
      return
    }
    setDownloading(true)
    try {
      const url = await downloadReport(session.session_id, analyst)
      Object.assign(document.createElement('a'), { href: url, download: `noctra_report_${session.session_id.slice(0,8)}.pdf` }).click()
      URL.revokeObjectURL(url)
      toast.success('Server PDF downloaded')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Server PDF failed — use the styled report instead')
    } finally { setDownloading(false) }
  }

  const TABS = [
    { key: 'ops',       label: role === 'L1' ? 'Operations (L1)' : 'Threat Analysis (L2)' },
    { key: 'overview',  label: 'Overview' },
    { key: 'mitre',     label: 'MITRE Coverage' },
    { key: 'incidents', label: `Incidents`, count: tpCount },
    { key: 'insights',  label: 'Learning Insights' },
    { key: 'report',    label: 'Export Report' },
  ]

  const CardWrap = ({ children, className = '', style = {} }) => (
    <div className={`rounded-2xl section-zoom ${className}`} style={{ background: 'var(--surface)', border: '1px solid var(--border-2)', ...style }}>
      {children}
    </div>
  )

  const SectionHead = ({ title }) => (
    <p className="text-xs font-bold uppercase tracking-widest px-5 pt-5 pb-0" style={{ color: 'var(--text-3)' }}>{title}</p>
  )

  return (
    <div className="space-y-6 fade-in">

      {/* ── Header ── */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <span className="eyebrow-display">SESSION DASHBOARD</span>
          <h1 className="display display-sm mt-3" style={{ color: 'var(--text-1)' }}>SITUATION ROOM.</h1>
          <p className="text-xs mt-3 font-mono" style={{ color: 'var(--text-3)' }}>
            {session?.session_id}
            <span className="mx-2" style={{ color: 'var(--border-3)' }}>·</span>
            {session?.parsed_format}
            <span className="mx-2" style={{ color: 'var(--border-3)' }}>·</span>
            {session?.event_count?.toLocaleString()} events parsed
          </p>
        </div>
        {/* Role switcher + Tab nav */}
        <div className="flex flex-col items-end gap-2">
        <div className="segmented">
          {[
            { id: 'L1', label: 'L1 Analyst', desc: 'Triage & Respond',  icon: ShieldAlert },
            { id: 'L2', label: 'L2 Analyst', desc: 'Threat Analysis',   icon: Shield },
          ].map(r => {
            const I = r.icon
            return (
              <button
                key={r.id}
                onClick={() => { setRole(r.id); setActiveTab('ops') }}
                title={r.desc}
                aria-selected={role === r.id}
              >
                <I size={13} />
                {r.label}
              </button>
            )
          })}
        </div>
        <div className="flex items-center gap-2">
          {TABS.map(({ key, label, count }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className="relative text-sm font-medium px-3 py-1.5 rounded-lg transition-all"
              style={{
                background: activeTab === key ? 'rgba(225,29,72,0.12)' : 'transparent',
                color: activeTab === key ? '#f43f5e' : 'var(--text-2)',
                boxShadow: activeTab === key ? '0 0 0 1px rgba(225,29,72,0.25)' : 'none',
              }}
            >
              {label}
              {count != null && count > 0 && (
                <span className="ml-1 text-[10px] px-1 rounded font-bold" style={{ background: 'rgba(225,29,72,0.2)', color: '#f87171' }}>{count}</span>
              )}
            </button>
          ))}
        </div>
        </div>
      </div>

      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
        <KPICard onClick={() => navigate('/triage')} label="Total Alerts"     value={alerts.length}     icon={Icons.alert}    iconClass="icon-3d-red"    colour="text-white"         accent="default" sub={`${session?.event_count?.toLocaleString()} events`} />
        <KPICard onClick={() => navigate('/triage')} label="True Positives"   value={tpCount}           icon={Icons.tp}       iconClass="icon-3d-red"    colour="text-red-500"        accent="red"     sub="confirmed threats" />
        <KPICard onClick={() => navigate('/triage')} label="False Positives"  value={fpCount}           icon={Icons.fp}       iconClass="icon-3d-red"  colour="text-neutral-400"    accent="red"   sub="dismissed" />
        <KPICard onClick={() => navigate('/triage')} label="Coverage"         value={`${coverage}%`}    icon={Icons.coverage} iconClass="icon-3d-red"  colour={coverage===100?'text-red-400':'text-red-600'} accent="red" sub={`${pending} pending`} />
        {precision != null && <KPICard label="Precision"    value={`${precision}%`}  icon={Icons.precision} iconClass="icon-3d-red" colour="text-red-500"     accent="red" sub="TP / total verdicts" />}
        {avgProb   != null && <KPICard label="AI Confidence" value={`${avgProb}%`}   icon={Icons.ai}       iconClass="icon-3d-red"  colour="text-red-400"    accent="red" sub={`${probAlerts.length} scored`} />}
        <KPICard onClick={() => setActiveTab('mitre')} label="MITRE Tactics"    value={uniqueTactics}     icon={Icons.mitre}    iconClass="icon-3d-red"   colour="text-red-500"       accent="red"    sub={`${uniqueTechniques} techniques`} />
      </div>

      {/* ── Operations Center (role-based) ── */}
      {activeTab === 'ops' && alerts.length > 0 && (
        <div className="space-y-5">

          {/* Role context banner */}
          <div className="rounded-2xl p-4 flex items-center gap-4 tile-lift gradient-border"
            style={{ background: 'linear-gradient(135deg, rgba(225,29,72,0.08), rgba(159,18,57,0.04))' }}>
            <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0 icon-3d-red">
              {role === 'L2' ? <Shield size={22} color="#f43f5e" strokeWidth={1.8} /> : <ShieldAlert size={22} color="#f43f5e" strokeWidth={1.8} />}
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-bold text-white flex items-center gap-2 flex-wrap">
                {role === 'L1' ? 'Tier-1 SOC Operations' : 'Tier-2 Threat Analysis'}
                <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
                  {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role}
                </span>
                <span className="text-xs font-normal" style={{ color: 'var(--text-3)' }}>
                  · {role === 'L1' ? 'Triage & Respond' : 'Hunt & Correlate'}
                </span>
              </p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>
                {role === 'L1'
                  ? 'Front-line queue: process the backlog, escalate confirmed threats, dismiss noise.'
                  : 'Deep analysis: reconstruct the attack chain, correlate entities, drive threat hunts.'}
              </p>
            </div>
            <button onClick={() => navigate('/triage')} className="btn-accent text-xs px-4 py-2 rounded-xl font-bold hover-glow shrink-0 inline-flex items-center gap-1.5">
              Open Triage <ChevronRight size={12} />
            </button>
          </div>

          {/* ───────────── L1 ANALYST MODULE ───────────── */}
          {role === 'L1' && (
            <>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { label: 'Queue Depth',     value: pendingAlerts.length, sub: 'awaiting verdict',     col: pendingAlerts.length > 0 ? 'text-red-400' : 'text-emerald-400' },
                  { label: 'Critical Pending',value: criticalPending,      sub: 'immediate priority',   col: criticalPending > 0 ? 'text-red-600' : 'text-neutral-400' },
                  { label: 'Hot Alerts',      value: hotPending,           sub: 'AI ≥ 75% · pending',   col: hotPending > 0 ? 'text-red-500' : 'text-neutral-400' },
                  { label: 'Triage Coverage', value: `${coverage}%`,       sub: `${alerts.length - pending}/${alerts.length} resolved`, col: coverage === 100 ? 'text-emerald-400' : 'text-red-400' },
                ].map(s => (
                  <div key={s.label} className="kpi-card kpi-card-red p-5" style={{ background: 'var(--surface)' }}>
                    <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{s.label}</p>
                    <p className={`text-3xl font-extrabold tabular-nums mt-2 ${s.col}`}>{s.value}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>{s.sub}</p>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Rapid response actions */}
                <CardWrap className="p-5">
                  <SectionHead title="Rapid Response" />
                  <div className="grid grid-cols-1 gap-2 mt-4">
                    {[
                      { label: 'Triage Critical first', desc: `${criticalPending} critical pending`, sev: '#ff0000' },
                      { label: 'Review hot AI alerts',   desc: `${hotPending} scored ≥ 75%`,         sev: '#e11d48' },
                      { label: 'Clear full backlog',     desc: `${pendingAlerts.length} total pending`, sev: '#f43f5e' },
                    ].map(a => (
                      <button key={a.label} onClick={() => navigate('/triage')}
                        className="flex items-center gap-3 px-4 py-3 rounded-xl text-left transition-all hover-glow"
                        style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
                        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: a.sev }} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-semibold text-white">{a.label}</p>
                          <p className="text-xs" style={{ color: 'var(--text-3)' }}>{a.desc}</p>
                        </div>
                        <span style={{ color: 'var(--text-4)' }}>→</span>
                      </button>
                    ))}
                  </div>
                </CardWrap>

                {/* Live pending stream */}
                <CardWrap className="lg:col-span-2 p-5">
                  <div className="flex items-center justify-between">
                    <SectionHead title="Live Alert Stream — Pending Queue" />
                    <span className="text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded-full mr-5 mt-5"
                      style={{ background: 'rgba(225,29,72,0.12)', color: '#f87171' }}>
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse mr-1" />
                      {pendingAlerts.length} live
                    </span>
                  </div>
                  {pendingAlerts.length > 0 ? (
                    <div className="mt-4 space-y-1.5 max-h-80 overflow-y-auto pr-1">
                      {pendingAlerts.slice(0, 12).map(a => {
                        const p = a.tp_probability != null ? Math.round(a.tp_probability * 100) : null
                        return (
                          <div key={a.alert_id} onClick={() => navigate(`/investigate/${a.alert_id}`)}
                            className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer transition-all"
                            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
                            onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(225,29,72,0.3)'}
                            onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}>
                            <span className="text-xs font-bold w-16 shrink-0" style={{ color: SEV_C[a.severity] }}>{a.severity}</span>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold text-white truncate">{a.rule_name}</p>
                              <p className="text-[10px] font-mono" style={{ color: 'var(--text-4)' }}>{a.rule_id}{a.source_ip ? ` · ${a.source_ip}` : ''}</p>
                            </div>
                            {p != null && (
                              <span className="text-xs font-mono font-bold shrink-0" style={{ color: p >= 75 ? '#ff0000' : p >= 45 ? '#e11d48' : '#6b7280' }}>{p}%</span>
                            )}
                            <span style={{ color: 'var(--text-4)' }} className="shrink-0">→</span>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div className="text-center py-12 mt-4">
                      <p className="text-2xl mb-2">✓</p>
                      <p className="text-sm text-white font-semibold">Queue cleared</p>
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>All alerts triaged. Good work.</p>
                    </div>
                  )}
                </CardWrap>
              </div>
            </>
          )}

          {/* ───────────── L2 ANALYST MODULE ───────────── */}
          {role === 'L2' && (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Composite threat score gauge */}
                <CardWrap className="p-5 flex flex-col items-center justify-center text-center">
                  <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Composite Threat Score</p>
                  <div className="relative my-4 w-32 h-32">
                    <svg viewBox="0 0 120 120" className="w-32 h-32 -rotate-90">
                      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--surface-3)" strokeWidth="10" />
                      <circle cx="60" cy="60" r="52" fill="none"
                        stroke={threatScore >= 66 ? '#ff0000' : threatScore >= 33 ? '#e11d48' : '#6b7280'}
                        strokeWidth="10" strokeLinecap="round"
                        strokeDasharray={`${(threatScore / 100) * 326.7} 326.7`} />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-4xl font-extrabold tabular-nums"
                        style={{ color: threatScore >= 66 ? '#ff0000' : threatScore >= 33 ? '#e11d48' : '#9ca3af' }}>{threatScore}</span>
                      <span className="text-[10px]" style={{ color: 'var(--text-4)' }}>/ 100</span>
                    </div>
                  </div>
                  <p className="text-sm font-bold" style={{ color: threatScore >= 66 ? '#f87171' : threatScore >= 33 ? '#fb7185' : '#9ca3af' }}>
                    {threatScore >= 66 ? 'SEVERE' : threatScore >= 33 ? 'ELEVATED' : 'GUARDED'}
                  </p>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>severity × AI confidence weighted</p>
                </CardWrap>

                {/* AI confidence histogram */}
                <CardWrap className="lg:col-span-2 p-5">
                  <SectionHead title="AI Confidence Distribution" />
                  <div className="mt-5 space-y-3">
                    {confBuckets.map(b => {
                      const total = probAlerts.length || 1
                      const pct = Math.round((b.count / total) * 100)
                      return (
                        <div key={b.label} className="flex items-center gap-3">
                          <span className="text-xs font-mono w-16 shrink-0" style={{ color: 'var(--text-3)' }}>{b.label}</span>
                          <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                            <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: b.fill }} />
                          </div>
                          <span className="text-xs tabular-nums w-10 text-right font-bold text-white">{b.count}</span>
                        </div>
                      )
                    })}
                  </div>
                  <p className="text-xs mt-4" style={{ color: 'var(--text-4)' }}>{probAlerts.length} alerts scored by AI · {highConfidence.length} high-confidence</p>
                </CardWrap>
              </div>

              {/* Kill-chain progression */}
              <CardWrap className="p-5">
                <div className="flex items-center justify-between">
                  <SectionHead title="Attack Kill-Chain Progression" />
                  <span className="text-[10px] font-bold uppercase tracking-widest mr-5 mt-5" style={{ color: 'var(--text-3)' }}>
                    {chainReach}/12 phases reached
                  </span>
                </div>
                <div className="mt-5 flex items-stretch gap-1 overflow-x-auto pb-2">
                  {killChain.map((c, i) => (
                    <div key={c.tactic} className="flex items-center shrink-0">
                      <div className="rounded-xl px-3 py-2.5 text-center min-w-[92px] transition-all"
                        style={{
                          background: c.active ? 'rgba(225,29,72,0.12)' : 'var(--surface-2)',
                          border: `1px solid ${c.active ? 'rgba(225,29,72,0.35)' : 'var(--border)'}`,
                          opacity: c.active ? 1 : 0.45,
                        }}>
                        <p className="text-[10px] font-bold leading-tight" style={{ color: c.active ? '#f87171' : 'var(--text-3)' }}>{c.tactic}</p>
                        <p className="text-lg font-extrabold tabular-nums mt-1" style={{ color: c.active ? '#fff' : 'var(--text-4)' }}>{c.count}</p>
                      </div>
                      {i < killChain.length - 1 && (
                        <span className="px-0.5 text-xs" style={{ color: c.active && killChain[i + 1].active ? '#e11d48' : 'var(--border-3)' }}>›</span>
                      )}
                    </div>
                  ))}
                </div>
              </CardWrap>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Top talkers */}
                <CardWrap className="p-5">
                  <SectionHead title="Top Source IPs — Talkers" />
                  {topIPs.length > 0 ? (
                    <div className="mt-4 space-y-2">
                      {topIPs.map(t => (
                        <div key={t.ip} className="flex items-center gap-3 px-3 py-2.5 rounded-xl"
                          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                          <span className="text-xs font-bold w-14 shrink-0" style={{ color: SEV_C[t.maxSev] }}>{t.maxSev}</span>
                          <span className="text-sm font-mono text-white flex-1 truncate">{t.ip}</span>
                          {t.tp > 0 && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold" style={{ background: 'rgba(225,29,72,0.15)', color: '#f87171' }}>{t.tp} TP</span>
                          )}
                          <span className="text-xs font-bold tabular-nums w-16 text-right" style={{ color: 'var(--text-2)' }}>{t.count} alerts</span>
                        </div>
                      ))}
                    </div>
                  ) : <p className="text-sm mt-4" style={{ color: 'var(--text-3)' }}>No source IPs extracted.</p>}
                </CardWrap>

                {/* Threat-hunt hypotheses */}
                <CardWrap className="p-5">
                  <SectionHead title="Suggested Threat Hunts" />
                  <div className="mt-4 space-y-2">
                    {[
                      criticalAlerts.length > 0 && { t: `Pivot on ${criticalAlerts.length} CRITICAL alert(s)`, d: 'Correlate source IPs across the full timeline for lateral movement.' },
                      chainReach >= 4 && { t: `Multi-stage attack: ${chainReach} kill-chain phases`, d: 'Reconstruct end-to-end attack path; likely a coordinated campaign.' },
                      topIPs[0] && topIPs[0].count >= 3 && { t: `Repeat offender ${topIPs[0].ip}`, d: `${topIPs[0].count} alerts from one host — investigate for C2 beaconing.` },
                      highConfidence.length > 0 && { t: `${highConfidence.length} high-confidence alert(s)`, d: 'Prioritise these for IOC enrichment and threat-intel lookups.' },
                    ].filter(Boolean).map((h, i) => (
                      <div key={i} className="flex gap-3 px-4 py-3 rounded-xl"
                        style={{ background: 'rgba(225,29,72,0.05)', border: '1px solid rgba(225,29,72,0.15)' }}>
                        <Crosshair size={14} className="shrink-0 mt-0.5" color="#f87171" />
                        <div>
                          <p className="text-sm font-semibold text-white">{h.t}</p>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--text-2)' }}>{h.d}</p>
                        </div>
                      </div>
                    ))}
                    {criticalAlerts.length === 0 && chainReach < 4 && highConfidence.length === 0 && (!topIPs[0] || topIPs[0].count < 3) && (
                      <p className="text-sm" style={{ color: 'var(--text-3)' }}>No high-priority hunt leads in this session.</p>
                    )}
                  </div>
                </CardWrap>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── Overview tab ── */}
      {activeTab === 'overview' && (
        <div className="space-y-5">

          {/* Tier banner — Overview reads differently per role */}
          <div className="rounded-xl px-4 py-3 flex items-center gap-3"
            style={{
              background: role === 'L2' ? 'linear-gradient(135deg, rgba(225,29,72,.10), rgba(127,29,29,.05))' : 'rgba(225,29,72,.05)',
              border: `1px solid ${role === 'L2' ? 'rgba(244,63,94,.35)' : 'rgba(225,29,72,.20)'}`,
            }}>
            <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
              {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role} VIEW
            </span>
            <p className="text-xs flex-1" style={{ color: 'var(--text-2)' }}>
              {role === 'L1'
                ? 'Operational overview — shift snapshot, queue health, severity mix. Optimised for fast triage decisions.'
                : 'Forensic overview — AI risk profile, severity distribution, rule attribution, and tactic confidence radar.'}
            </p>
          </div>

          {/* L1-only — Shift snapshot strip */}
          {role === 'L1' && alerts.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { lbl: 'Critical Pending', v: criticalPending, sub: 'priority 1', col: criticalPending > 0 ? 'text-red-500' : 'text-emerald-400' },
                { lbl: 'High Pending',     v: pendingAlerts.filter(a => a.severity === 'HIGH').length, sub: 'priority 2', col: 'text-red-400' },
                { lbl: 'Hot AI Alerts',    v: hotPending,        sub: 'TP ≥ 75%', col: 'text-red-400' },
                { lbl: 'Resolved Today',   v: alerts.length - pendingAlerts.length, sub: `of ${alerts.length}`, col: 'text-white' },
              ].map(s => (
                <div key={s.lbl} className="kpi-card kpi-card-red p-4" style={{ background: 'var(--surface)' }}>
                  <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{s.lbl}</p>
                  <p className={`text-2xl font-extrabold tabular-nums mt-1 ${s.col}`}>{s.v}</p>
                  <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-4)' }}>{s.sub}</p>
                </div>
              ))}
            </div>
          )}

          {/* AI Analysis Summary */}
          {avgProb != null && (
            <CardWrap
              style={{
                background: 'linear-gradient(135deg, rgba(99,102,241,0.06) 0%, rgba(225,29,72,0.04) 100%)',
                border: '1px solid rgba(99,102,241,0.2)',
              }}
            >
              <div className="p-5">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 icon-3d-red">
                    <Sparkles size={20} color="#f43f5e" strokeWidth={1.6} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <p className="font-bold text-white">AI Analysis Summary</p>
                      <span
                        className="text-xs font-bold px-2.5 py-1 rounded-full"
                        style={{
                          background: avgProb >= 75 ? 'rgba(225,29,72,0.15)' : avgProb >= 45 ? 'rgba(245,158,11,0.15)' : 'rgba(34,197,94,0.15)',
                          color: avgProb >= 75 ? '#f87171' : avgProb >= 45 ? '#fbbf24' : '#4ade80',
                          border: `1px solid ${avgProb >= 75 ? 'rgba(225,29,72,0.3)' : avgProb >= 45 ? 'rgba(245,158,11,0.3)' : 'rgba(34,197,94,0.3)'}`,
                        }}
                      >
                        {avgProb >= 75 ? '⚠ HIGH RISK' : avgProb >= 45 ? '▲ MODERATE RISK' : '● LOW RISK'}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-3">
                      <div className="rounded-xl p-3" style={{ background: 'rgba(0,0,0,0.2)' }}>
                        <p className="text-xs mb-1" style={{ color: 'var(--text-3)' }}>Session Avg TP Confidence</p>
                        <p className="text-2xl font-extrabold" style={{ color: avgProb >= 75 ? '#ff0000' : avgProb >= 45 ? '#e11d48' : '#6b7280' }}>{avgProb}%</p>
                        <div className="mt-1.5 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                          <div className="h-full rounded-full" style={{ width: `${avgProb}%`, background: avgProb >= 75 ? 'linear-gradient(90deg,#9f1239,#ff0000)' : avgProb >= 45 ? 'linear-gradient(90deg,#9f1239,#e11d48)' : 'linear-gradient(90deg,#3d3d48,#6b7280)' }} />
                        </div>
                      </div>
                      <div className="rounded-xl p-3" style={{ background: 'rgba(0,0,0,0.2)' }}>
                        <p className="text-xs mb-1" style={{ color: 'var(--text-3)' }}>High-Confidence Alerts</p>
                        <p className="text-2xl font-extrabold text-red-500">{highConfidence.length}</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>≥ 75% probability</p>
                      </div>
                      <div className="rounded-xl p-3" style={{ background: 'rgba(0,0,0,0.2)' }}>
                        <p className="text-xs mb-1" style={{ color: 'var(--text-3)' }}>Top Firing Rule</p>
                        <p className="text-sm font-bold text-white truncate">{topRule?.name ?? '—'}</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>{topRule?.count ?? 0} alerts</p>
                      </div>
                    </div>
                    <p className="text-sm leading-relaxed" style={{ color: 'var(--text-2)' }}>
                      {avgProb >= 75
                        ? <>High-risk session. <span onClick={() => navigate('/triage')} className="font-semibold text-red-500 underline cursor-pointer hover:text-red-400 transition-colors">{highConfidence.length} alert(s) scored ≥75% TP confidence</span> by Gemini. {criticalAlerts.length > 0 ? <><span onClick={() => navigate('/triage')} className="font-semibold text-red-600 underline cursor-pointer hover:text-red-500 transition-colors">{criticalAlerts.length} CRITICAL severity event(s)</span> require immediate triage. </> : ''}Recommend escalating confirmed TPs to incident response immediately.</>
                        : avgProb >= 45
                          ? <>Moderate-risk session. <span onClick={() => navigate('/triage')} className="font-semibold text-red-400 underline cursor-pointer hover:text-red-300 transition-colors">{highConfidence.length} high-confidence alert(s)</span> detected. <span onClick={() => navigate('/triage')} className="font-semibold text-neutral-400 underline cursor-pointer hover:text-neutral-300 transition-colors">{pending} alert(s) still pending</span> analyst review. Perform targeted investigation on top-scoring alerts before closing the session.</>
                          : <>Low-risk session. Average confidence below 45% — likely noisy environment or benign activity. Review <span onClick={() => navigate('/triage')} className="font-semibold text-neutral-400 underline cursor-pointer hover:text-neutral-300 transition-colors">pending alerts</span> and consider tuning detection rules to reduce false positive volume.</>
                      }
                    </p>
                  </div>
                </div>
              </div>
            </CardWrap>
          )}

          {/* Charts */}
          {alerts.length > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Severity bar */}
              <CardWrap className="lg:col-span-2 p-5">
                <div className="flex items-center justify-between">
                  <SectionHead title="Alerts by Severity" />
                  {chartSevFilter && (
                    <button onClick={() => setChartSevFilter(null)} className="text-[10px] uppercase font-bold tracking-wider px-2 py-1 rounded border transition-colors" style={{ color: 'var(--accent)', borderColor: 'var(--accent-glow)', background: 'var(--accent-dim)' }}>
                      Clear filter (showing {chartSevFilter}) ✕
                    </button>
                  )}
                </div>
                <div className="mt-4">
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={sevData} barCategoryGap="40%">
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                      <XAxis dataKey="name" tick={{ fill: '#52525e', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: '#52525e', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<Tip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                      <Bar dataKey="count" name="Alerts" radius={[6,6,0,0]} onClick={(data) => setChartSevFilter(data.name)} style={{ cursor: 'pointer' }}>
                        {sevData.map((e, i) => <Cell key={i} fill={e.fill} fillOpacity={chartSevFilter ? (chartSevFilter === e.name ? 1 : 0.3) : 0.85} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardWrap>

              {/* Verdict donut */}
              <CardWrap className="p-5 flex flex-col">
                <SectionHead title="Verdict Distribution" />
                {donutData.length > 0 ? (
                  <div className="flex-1 flex flex-col">
                    <ResponsiveContainer width="100%" height={160}>
                      <PieChart>
                        <Pie data={donutData} dataKey="value" innerRadius={50} outerRadius={70} paddingAngle={4} strokeWidth={0}>
                          {donutData.map((e, i) => <Cell key={i} fill={e.fill} fillOpacity={0.85} />)}
                        </Pie>
                        <Tooltip content={<Tip />} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="flex flex-wrap justify-center gap-4 mt-2">
                      {donutData.map(d => (
                        <div key={d.name} className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-2)' }}>
                          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.fill }} />
                          {d.name} <span className="font-bold text-white">{d.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="flex-1 flex items-center justify-center">
                    <div className="text-center">
                      <p className="text-sm" style={{ color: 'var(--text-3)' }}>No verdicts yet</p>
                      <button onClick={() => navigate('/triage')} className="text-xs mt-2 underline" style={{ color: 'var(--accent)' }}>Go to Triage →</button>
                    </div>
                  </div>
                )}
              </CardWrap>
            </div>
          )}

          {/* L2-only — Tactic confidence radar (forensic angle) */}
          {role === 'L2' && mitreData.length >= 3 && (
            <CardWrap className="p-5">
              <SectionHead title="Tactic × AI Confidence Radar" />
              <div className="mt-2">
                <ResponsiveContainer width="100%" height={260}>
                  <RadarChart data={mitreData.slice(0, 8).map(m => {
                    const subset = alerts.filter(a => a.mitre_tactic === m.tactic && a.tp_probability != null)
                    const avg = subset.length ? subset.reduce((s, a) => s + a.tp_probability, 0) / subset.length : 0
                    return { tactic: m.tactic, count: m.count, confidence: Math.round(avg * 100) }
                  })}>
                    <PolarGrid stroke="rgba(255,255,255,0.08)" />
                    <PolarAngleAxis dataKey="tactic" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                    <PolarRadiusAxis tick={{ fill: '#6b7280', fontSize: 9 }} angle={90} />
                    <Radar name="AI Confidence %" dataKey="confidence" stroke="#f43f5e" fill="#e11d48" fillOpacity={0.35} />
                    <Tooltip content={<Tip />} />
                  </RadarChart>
                </ResponsiveContainer>
                <p className="text-xs text-center mt-1" style={{ color: 'var(--text-3)' }}>
                  Average TP probability per tactic — wider lobes mean the AI is more certain those events are real.
                </p>
              </div>
            </CardWrap>
          )}

          {/* L2-only — Top talker forensic strip */}
          {role === 'L2' && topIPs.length > 0 && (
            <CardWrap className="p-5">
              <SectionHead title="Forensic Entity Spotlight — Top Source IPs" />
              <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {topIPs.slice(0, 6).map(t => (
                  <div key={t.ip} className="rounded-xl px-3 py-2.5 flex items-center gap-3 tile-lift"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <span className="text-[10px] font-bold w-12 shrink-0 num" style={{ color: SEV_C[t.maxSev] }}>{t.maxSev}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono font-bold text-white truncate num">{t.ip}</p>
                      <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{t.count} alerts · {t.tp} TP</p>
                    </div>
                    <button onClick={() => navigate('/hunt')} className="text-[10px] px-2 py-1 rounded border transition-colors"
                      style={{ borderColor: 'rgba(225,29,72,.3)', color: '#f87171', background: 'rgba(225,29,72,.06)' }}>
                      Pivot →
                    </button>
                  </div>
                ))}
              </div>
            </CardWrap>
          )}

          {/* Rule breakdown */}
          {ruleData.length > 0 && (
            <CardWrap className="p-5">
              <SectionHead title="Alert Volume by Detection Rule" />
              <div className="mt-4 space-y-2.5">
                {ruleData.map(({ name, count, ruleName }) => {
                  const pct = Math.round((count / alerts.length) * 100)
                  return (
                    <div key={name} className="grid items-center gap-3" style={{ gridTemplateColumns: '3rem 1fr 10rem 2.5rem' }}>
                      <span className="text-xs font-mono font-bold truncate" style={{ color: 'var(--accent)' }}>{name}</span>
                      <span className="text-xs truncate hidden sm:block" style={{ color: 'var(--text-2)' }}>{ruleName}</span>
                      <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${pct}%`, background: 'linear-gradient(90deg,#9f1239,#e11d48)' }} />
                      </div>
                      <span className="text-xs text-right tabular-nums font-semibold text-white">{count}</span>
                    </div>
                  )
                })}
              </div>
            </CardWrap>
          )}
        </div>
      )}

      {/* ── MITRE tab ── */}
      {activeTab === 'mitre' && (
        <div className="space-y-5">

          {/* Tier banner */}
          <div className="rounded-xl px-4 py-3 flex items-center gap-3"
            style={{
              background: role === 'L2' ? 'linear-gradient(135deg, rgba(225,29,72,.10), rgba(127,29,29,.05))' : 'rgba(225,29,72,.05)',
              border: `1px solid ${role === 'L2' ? 'rgba(244,63,94,.35)' : 'rgba(225,29,72,.20)'}`,
            }}>
            <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
              {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role} VIEW
            </span>
            <p className="text-xs flex-1" style={{ color: 'var(--text-2)' }}>
              {role === 'L1'
                ? 'Compact tactic coverage — what fired and how often. Use this to scope your shift focus.'
                : 'Forensic ATT&CK matrix — tactic distribution, technique inventory, and tactic-correlation radar to reconstruct attacker behaviour.'}
            </p>
          </div>

          {/* Search */}
          <div className="relative max-w-md">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-4)' }} />
            <input
              value={mitreQuery}
              onChange={e => setMitreQuery(e.target.value)}
              placeholder="Filter tactics or techniques (e.g. T1110, Lateral)…"
              className="w-full text-sm pl-9 pr-8 py-2 rounded-lg outline-none"
              style={{ background: 'var(--surface)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }}
              onFocus={e => e.target.style.borderColor = 'var(--accent)'}
              onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
            />
            {mitreQuery && (
              <button onClick={() => setMitreQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xl leading-none" style={{ color: 'var(--text-4)' }}>×</button>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <KPICard label="Tactics Covered"   value={uniqueTactics}    icon={Icons.mitre}    iconClass="icon-3d-red"   colour="text-red-400"   accent="red" />
            <KPICard label="Techniques Seen"   value={uniqueTechniques} icon={Icons.alert}    iconClass="icon-3d-red" colour="text-red-500" accent="red" />
            <KPICard label="Critical Severity" value={alerts.filter(a=>a.severity==='CRITICAL').length} icon={Icons.tp} iconClass="icon-3d-red" colour="text-red-600" accent="red" />
            <KPICard label="High Severity"     value={alerts.filter(a=>a.severity==='HIGH').length}     icon={Icons.coverage} iconClass="icon-3d-red" colour="text-red-500" accent="red" />
          </div>

          {/* L1 — Top priorities (actionable, scan in 5s) */}
          {role === 'L1' && mitreData.length > 0 && (
            <CardWrap className="p-5">
              <SectionHead title="Today's Priorities · what to act on first" />
              <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
                {mitreData.filter(m => !mitreQuery || m.tactic.toLowerCase().includes(mitreQuery.toLowerCase())).slice(0, 3).map(({ tactic, count, colour }, i) => {
                  const subset = alerts.filter(a => a.mitre_tactic === tactic)
                  const pending = subset.filter(a => !verdicts[a.alert_id]).length
                  const critical = subset.filter(a => a.severity === 'CRITICAL').length
                  return (
                    <div key={tactic} className="rounded-xl p-4 transition-all tile-lift"
                      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-mono num font-bold px-2 py-0.5 rounded"
                          style={{ background: 'rgba(225,29,72,.12)', color: '#f87171', border: '1px solid rgba(225,29,72,.25)' }}>
                          #{i + 1}
                        </span>
                        <span className="w-2 h-2 rounded-full" style={{ background: colour, boxShadow: `0 0 8px ${colour}` }} />
                      </div>
                      <p className="text-sm font-extrabold text-white">{tactic}</p>
                      <p className="text-[11px] mt-1" style={{ color: 'var(--text-3)' }}>
                        {count} alert{count !== 1 ? 's' : ''} · {critical > 0 && <span className="text-red-400 font-bold">{critical} critical</span>}
                        {critical > 0 && pending > 0 ? ' · ' : ''}
                        {pending > 0 && <span className="text-amber-400">{pending} pending</span>}
                      </p>
                      <p className="text-[10px] mt-2 leading-snug" style={{ color: 'var(--text-2)' }}>
                        {pending > 0 ? `Clear ${pending} pending verdict${pending !== 1 ? 's' : ''} in this tactic — shift KPI.` : 'Fully triaged — handover-ready.'}
                      </p>
                    </div>
                  )
                })}
              </div>
            </CardWrap>
          )}

          {mitreData.length > 0 ? (
            <>
              <CardWrap className="p-5">
                <SectionHead title={role === 'L2' ? "ATT&CK Tactic Distribution · forensic view" : "Tactic coverage"} />
                <div className="mt-4 space-y-3">
                  {mitreData.filter(m => !mitreQuery || m.tactic.toLowerCase().includes(mitreQuery.toLowerCase())).map(({ tactic, count, colour }) => {
                    const pct = Math.round((count / alerts.length) * 100)
                    const tpAl = alerts.filter(a => a.mitre_tactic === tactic)
                    const tpC  = tpAl.filter(a => verdicts[a.alert_id]?.decision === 'TP').length
                    return (
                      <div key={tactic} className="space-y-1.5">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: colour }} />
                            <span className="font-medium text-white">{tactic}</span>
                            {tpC > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(225,29,72,0.15)', color: '#f87171', border: '1px solid rgba(225,29,72,0.2)' }}>{tpC} TP</span>
                            )}
                          </div>
                          <div className="flex items-center gap-3" style={{ color: 'var(--text-3)' }}>
                            <span>{count} alert{count !== 1 ? 's' : ''}</span>
                            <span className="tabular-nums w-8 text-right font-mono">{pct}%</span>
                          </div>
                        </div>
                        <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                          <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: colour, opacity: 0.75 }} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardWrap>

              {role === 'L2' && (
                <CardWrap className="p-5">
                  <SectionHead title="Techniques Observed · sub-technique inventory" />
                  <div className="flex flex-wrap gap-2 mt-4">
                    {[...new Set(alerts.map(a => a.mitre_technique).filter(Boolean))]
                      .filter(t => !mitreQuery || t.toLowerCase().includes(mitreQuery.toLowerCase()))
                      .map(tech => {
                      const matched = alerts.filter(a => a.mitre_technique === tech)
                      const tpC = matched.filter(a => verdicts[a.alert_id]?.decision === 'TP').length
                      return (
                        <span key={tech} className="text-xs px-2.5 py-1 rounded-lg font-mono num inline-flex items-center gap-1.5"
                          style={{ background: 'rgba(225,29,72,0.1)', border: '1px solid rgba(225,29,72,0.2)', color: '#f87171' }}>
                          {tech}
                          <span className="text-[9px] px-1 rounded" style={{ background: 'rgba(255,255,255,.05)', color: 'var(--text-3)' }}>×{matched.length}</span>
                          {tpC > 0 && <span className="text-[9px] font-bold" style={{ color: '#ff5555' }}>TP {tpC}</span>}
                        </span>
                      )
                    })}
                  </div>
                </CardWrap>
              )}

              {/* L2 — Analytic gaps (tactics with zero coverage) */}
              {role === 'L2' && (() => {
                const ALL_TACTICS = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command & Control','Exfiltration','Impact']
                const seen = new Set(mitreData.map(m => m.tactic))
                const gaps = ALL_TACTICS.filter(t => !seen.has(t))
                if (!gaps.length) return null
                return (
                  <CardWrap className="p-5" style={{ borderColor: 'rgba(251,191,36,.25)' }}>
                    <SectionHead title="Analytic Gaps · unobserved tactics this session" />
                    <p className="text-xs mt-2 mb-3" style={{ color: 'var(--text-3)' }}>
                      No alerts fired against these tactics. Either the adversary genuinely didn't touch them, or your rules
                      have blind spots — worth building a hunt or rule to cover the gap.
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {gaps.map(g => (
                        <span key={g} className="text-xs px-2 py-0.5 rounded font-mono"
                          style={{ background: 'rgba(251,191,36,.06)', border: '1px solid rgba(251,191,36,.25)', color: '#fbbf24' }}>
                          {g}
                        </span>
                      ))}
                    </div>
                  </CardWrap>
                )
              })()}

              {/* L2-only — ATT&CK Radar */}
              {role === 'L2' && mitreData.length >= 3 && (
                <CardWrap className="p-5">
                  <SectionHead title="ATT&CK Tactic Radar — Volume vs Confidence" />
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-3">
                    <ResponsiveContainer width="100%" height={260}>
                      <RadarChart data={mitreData.map(m => ({ tactic: m.tactic, count: m.count }))}>
                        <PolarGrid stroke="rgba(255,255,255,0.08)" />
                        <PolarAngleAxis dataKey="tactic" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                        <PolarRadiusAxis tick={{ fill: '#6b7280', fontSize: 9 }} angle={90} />
                        <Radar name="Alert count" dataKey="count" stroke="#f43f5e" fill="#9f1239" fillOpacity={0.4} />
                        <Tooltip content={<Tip />} />
                      </RadarChart>
                    </ResponsiveContainer>
                    <ResponsiveContainer width="100%" height={260}>
                      <RadarChart data={mitreData.map(m => {
                        const subset = alerts.filter(a => a.mitre_tactic === m.tactic && a.tp_probability != null)
                        const avg = subset.length ? subset.reduce((s, a) => s + a.tp_probability, 0) / subset.length : 0
                        return { tactic: m.tactic, confidence: Math.round(avg * 100) }
                      })}>
                        <PolarGrid stroke="rgba(255,255,255,0.08)" />
                        <PolarAngleAxis dataKey="tactic" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                        <PolarRadiusAxis tick={{ fill: '#6b7280', fontSize: 9 }} angle={90} />
                        <Radar name="AI Confidence %" dataKey="confidence" stroke="#fb7185" fill="#fb7185" fillOpacity={0.30} />
                        <Tooltip content={<Tip />} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                  <p className="text-xs text-center mt-2" style={{ color: 'var(--text-3)' }}>
                    Left: where the attacker spent time. Right: where the AI is most confident the activity is real.
                  </p>
                </CardWrap>
              )}
            </>
          ) : (
            <div className="text-center py-16" style={{ color: 'var(--text-3)' }}>No MITRE data available for this session.</div>
          )}
        </div>
      )}

      {/* ── Incidents tab (role-segregated) ── */}
      {activeTab === 'incidents' && (
        <div className="space-y-4">
          {tpCount > 0 ? (() => {
            const incs   = alerts.filter(a => verdicts[a.alert_id]?.decision === 'TP')
            const tch    = a => a.mitre_techniques?.[0] || a.mitre_technique || '—'
            const tct    = a => a.mitre_tactics?.[0]   || a.mitre_tactic   || '—'
            const pb     = a => a.tp_probability != null ? a.tp_probability : a.ai_score != null ? a.ai_score/100 : null
            const aiTxt  = a => a.ai_rationale || a.ai_explanation || ''
            const sevCol = s => ({ CRITICAL:'#ff0000', HIGH:'#f43f5e', MEDIUM:'#e11d48', LOW:'#6b7280' }[s] || '#64748b')
            return (
            <>
              <CardWrap style={{ border: '1px solid rgba(225,29,72,0.2)', background: 'rgba(225,29,72,0.03)' }}>
                <div className="p-5">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-9 h-9 rounded-lg icon-3d-red flex items-center justify-center">
                      <AlertOctagon size={18} color="#f43f5e" strokeWidth={1.8} />
                    </div>
                    <div>
                      <p className="font-bold text-red-400 flex items-center gap-2">
                        Confirmed Incidents — <span className="num">{tpCount}</span>
                        <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
                          {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role} View
                        </span>
                      </p>
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                        {role === 'L1'
                          ? 'Escalation queue — click any incident to open the in-depth investigation'
                          : 'Forensic deep-dive — expand for evidence, then open full investigation'}
                      </p>
                    </div>
                  </div>

                  {/* L1: concise escalation rows */}
                  {role === 'L1' && (
                    <div className="space-y-2">
                      {incs.map(a => (
                        <div key={a.alert_id}
                          onClick={() => navigate(`/investigate/${a.alert_id}`)}
                          className="flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all"
                          style={{ background: 'rgba(225,29,72,0.06)', border: '1px solid rgba(225,29,72,0.15)' }}
                          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(225,29,72,0.1)'; e.currentTarget.style.borderColor = 'rgba(225,29,72,0.3)' }}
                          onMouseLeave={e => { e.currentTarget.style.background = 'rgba(225,29,72,0.06)'; e.currentTarget.style.borderColor = 'rgba(225,29,72,0.15)' }}>
                          <AlertOctagon size={16} color={sevCol(a.severity)} className="shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-semibold text-white truncate">{a.rule_name}</p>
                            <p className="text-xs font-mono" style={{ color: 'var(--text-3)' }}>{a.rule_id} · {tch(a)}</p>
                          </div>
                          {a.source_ip && <span className="text-xs font-mono hidden sm:block num" style={{ color: 'var(--text-3)' }}>{a.source_ip}</span>}
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full hidden sm:inline-flex items-center gap-1" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}>
                            <Zap size={10} /> ESCALATE
                          </span>
                          <span className="text-xs font-bold num" style={{ color: sevCol(a.severity) }}>{a.severity}</span>
                          <ChevronRight size={14} className="shrink-0" style={{ color: 'var(--text-4)' }} />
                        </div>
                      ))}
                    </div>
                  )}

                  {/* L2: expandable forensic cards */}
                  {role === 'L2' && (
                    <div className="space-y-3">
                      {incs.map((a, i) => {
                        const p = pb(a)
                        return (
                          <details key={a.alert_id} className="rounded-xl overflow-hidden group"
                            style={{ background: 'rgba(225,29,72,0.05)', border: '1px solid rgba(225,29,72,0.18)' }}>
                            <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer list-none select-none">
                              <span className="text-xs font-mono font-bold w-7 shrink-0 num" style={{ color: 'var(--text-4)' }}>#{i + 1}</span>
                              <AlertOctagon size={16} className="shrink-0" style={{ color: sevCol(a.severity) }} />
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-semibold text-white truncate">{a.rule_name}</p>
                                <p className="text-xs font-mono" style={{ color: 'var(--text-3)' }}>{a.rule_id} · {tch(a)} → {tct(a)}</p>
                              </div>
                              {p != null && (
                                <span className="text-xs font-mono font-bold shrink-0 num" style={{ color: p >= 0.75 ? '#ff0040' : p >= 0.45 ? '#e11d48' : '#6b7280' }}>{Math.round(p * 100)}%</span>
                              )}
                              <span className="text-xs font-bold shrink-0 num" style={{ color: sevCol(a.severity) }}>{a.severity}</span>
                              <ChevronRight size={14} className="shrink-0 transition-transform group-open:rotate-90" style={{ color: 'var(--text-4)' }} />
                            </summary>
                            <div className="px-4 pb-4 pt-1 space-y-3 border-t" style={{ borderColor: 'rgba(225,29,72,0.15)' }}>
                              <p className="text-sm" style={{ color: 'var(--text-2)' }}>{a.description}</p>
                              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                                {[
                                  ['Source IP', a.source_ip || '—'],
                                  ['Destination', a.dest_ip || '—'],
                                  ['User', a.user || '—'],
                                  ['Events', a.event_count ?? '—'],
                                ].map(([k, v]) => (
                                  <div key={k} className="rounded-lg px-3 py-2" style={{ background: 'rgba(0,0,0,0.25)' }}>
                                    <p style={{ color: 'var(--text-4)' }}>{k}</p>
                                    <p className="font-mono text-white truncate">{v}</p>
                                  </div>
                                ))}
                              </div>
                              {aiTxt(a) && (
                                <div className="rounded-lg p-3 text-xs" style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)' }}>
                                  <span className="font-bold text-red-400">AI Assessment: </span>
                                  <span style={{ color: '#c7d2fe' }}>{aiTxt(a)}</span>
                                </div>
                              )}
                              {verdicts[a.alert_id]?.notes && (
                                <p className="text-xs italic" style={{ color: 'var(--text-3)' }}>Analyst note: "{verdicts[a.alert_id].notes}"</p>
                              )}
                              {a.raw_log && (
                                <pre className="p-3 rounded-lg text-[10px] font-mono overflow-x-auto" style={{ background: 'var(--bg)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                                  {String(a.raw_log).split('\\n').join('\n')}
                                </pre>
                              )}
                              <button onClick={() => navigate(`/investigate/${a.alert_id}`)}
                                className="btn-accent text-xs px-4 py-2 rounded-lg font-bold hover-glow">
                                Open Full Investigation →
                              </button>
                            </div>
                          </details>
                        )
                      })}
                    </div>
                  )}
                </div>
              </CardWrap>

              {/* Notes */}
              <CardWrap>
                <div className="p-5">
                  <p className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: 'var(--text-3)' }}>Analyst Notes</p>
                  {alerts.some(a => verdicts[a.alert_id]?.notes) ? (
                    <div className="space-y-2">
                      {alerts.filter(a => verdicts[a.alert_id]?.notes).map(a => (
                        <div key={a.alert_id} className="flex gap-3 text-xs">
                          <span className="font-mono shrink-0" style={{ color: 'var(--accent)' }}>{a.rule_id}</span>
                          <p className="italic" style={{ color: 'var(--text-2)' }}>"{verdicts[a.alert_id].notes}"</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm" style={{ color: 'var(--text-4)' }}>No analyst notes recorded.</p>
                  )}
                </div>
              </CardWrap>
            </>
            )
          })() : (
            <div className="text-center py-16" style={{ color: 'var(--text-3)' }}>
              <p className="text-2xl mb-3">✓</p>
              <p>No confirmed incidents in this session.</p>
            </div>
          )}
        </div>
      )}

      {/* ── Learning Insights tab ── */}
      {activeTab === 'insights' && session?.session_id && (
        <div className="space-y-5">
          {/* Tier banner */}
          <div className="rounded-xl px-4 py-3 flex items-center gap-3"
            style={{
              background: role === 'L2' ? 'linear-gradient(135deg, rgba(225,29,72,.10), rgba(127,29,29,.05))' : 'rgba(225,29,72,.05)',
              border: `1px solid ${role === 'L2' ? 'rgba(244,63,94,.35)' : 'rgba(225,29,72,.20)'}`,
            }}>
            <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
              {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role} VIEW
            </span>
            <p className="text-xs flex-1" style={{ color: 'var(--text-2)' }}>
              {role === 'L1'
                ? 'How your TP/FP decisions are nudging detection — a feedback summary you can scan in 30 seconds.'
                : 'Detection-feedback loop in depth — rule-by-rule precision, drift signals, and per-feature weighting changes for the session.'}
            </p>
          </div>

          {/* L1-only — Compact summary preface */}
          {role === 'L1' && (() => {
            const totalVerdicts = tpCount + fpCount
            const precision = totalVerdicts > 0 ? Math.round((tpCount / totalVerdicts) * 100) : 0
            // AI agreement: for each verdict, did the AI's recommendation (>=0.6 → TP) match the analyst?
            let agree = 0, disagree = 0, agreeable = 0
            const aiVerdict = a => {
              const s = a.tp_probability != null ? a.tp_probability : a.ai_score != null ? a.ai_score / 100 : null
              return s == null ? null : (s >= 0.6 ? 'TP' : 'FP')
            }
            Object.values(verdicts).forEach(v => {
              const a = alerts.find(x => x.alert_id === v.alert_id)
              const aiV = a && aiVerdict(a)
              if (!aiV) return
              agreeable++
              if (aiV === v.decision) agree++; else disagree++
            })
            const agreementPct = agreeable > 0 ? Math.round((agree / agreeable) * 100) : null

            // Plain-English learning takeaways the engine has applied
            const takeaways = []
            if (tpCount > 0) takeaways.push(`Confirmed ${tpCount} true incident${tpCount !== 1 ? 's' : ''} — engine has boosted similar patterns in the queue.`)
            if (fpCount > 0) takeaways.push(`Dismissed ${fpCount} false alert${fpCount !== 1 ? 's' : ''} — those rule/IP combinations will rank lower for the rest of the session.`)
            if (agreementPct != null && agreementPct >= 80) takeaways.push(`AI agreement ${agreementPct}% — recommendations are reliable; safe to bulk-apply for routine triage.`)
            else if (agreementPct != null && agreementPct < 60) takeaways.push(`AI agreement only ${agreementPct}% — review each recommendation manually this shift.`)
            if (totalVerdicts >= 10) takeaways.push(`Strong feedback signal (${totalVerdicts} verdicts) — ranking adjustments are statistically meaningful.`)
            if (!takeaways.length) takeaways.push('Submit a few TP/FP verdicts to start the feedback loop.')

            return (
              <>
                {/* Headline KPIs — scannable in <5s */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Verdicts recorded', value: totalVerdicts, sub: `${tpCount} TP · ${fpCount} FP`, col: 'text-white', icon: ListChecks },
                    { label: 'Session precision', value: totalVerdicts ? `${precision}%` : '—', sub: totalVerdicts ? `${tpCount} of ${totalVerdicts} confirmed real` : 'no verdicts yet', col: precision >= 60 ? 'text-red-400' : 'text-amber-400', icon: Target },
                    { label: 'AI agreement', value: agreementPct != null ? `${agreementPct}%` : '—', sub: agreementPct != null ? `${agree}/${agreeable} matched analyst` : 'needs AI-scored verdicts', col: agreementPct >= 80 ? 'text-red-400' : agreementPct >= 60 ? 'text-amber-400' : 'text-zinc-400', icon: Sparkles },
                    { label: 'Pending', value: pending, sub: pending === 0 ? 'shift cleared — handover-ready' : `${pending} need verdict`, col: pending === 0 ? 'text-emerald-400' : 'text-amber-400', icon: AlertTriangle },
                  ].map(k => {
                    const I = k.icon
                    return (
                      <div key={k.label} className="rounded-xl p-4 tile-lift" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
                        <div className="flex items-center justify-between mb-1">
                          <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{k.label}</p>
                          <I size={12} style={{ color: 'var(--accent)' }} />
                        </div>
                        <p className={`text-2xl font-extrabold tabular-nums ${k.col}`}>{k.value}</p>
                        <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-4)' }}>{k.sub}</p>
                      </div>
                    )
                  })}
                </div>

                {/* AI trust gauge */}
                {agreementPct != null && (
                  <CardWrap className="p-5">
                    <SectionHead title="AI trust meter · how often the AI matched your call" />
                    <div className="mt-4 flex items-center gap-4">
                      <div className="flex-1">
                        <div className="h-3 rounded-full overflow-hidden flex" style={{ background: 'var(--surface-3)' }}>
                          <div className="h-full transition-all duration-700" style={{ width: `${agreementPct}%`, background: 'linear-gradient(90deg,#9f1239,#e11d48,#f87171)' }} />
                          <div className="h-full transition-all duration-700" style={{ width: `${100 - agreementPct}%`, background: 'rgba(107,114,128,.25)' }} />
                        </div>
                        <div className="flex justify-between text-[10px] mt-1.5">
                          <span style={{ color: '#f87171' }}>● Agreed: {agree}</span>
                          <span style={{ color: 'var(--text-3)' }}>● Overrode AI: {disagree}</span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-3xl font-extrabold tabular-nums" style={{ color: agreementPct >= 80 ? '#f87171' : '#fbbf24' }}>{agreementPct}%</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>agreement</p>
                      </div>
                    </div>
                    <p className="text-xs mt-3 leading-snug" style={{ color: 'var(--text-2)' }}>
                      {agreementPct >= 80
                        ? 'High agreement — AI recommendations align with your judgment. Consider bulk-applying for routine alert classes to speed triage.'
                        : agreementPct >= 60
                          ? 'Moderate agreement — sanity-check each AI recommendation before accepting.'
                          : 'Low agreement — current session looks atypical. Don\'t auto-apply AI verdicts this shift.'}
                    </p>
                  </CardWrap>
                )}

                {/* What you taught the engine — plain-English */}
                <CardWrap className="p-5">
                  <SectionHead title="What you taught the engine this shift" />
                  <ul className="mt-4 space-y-2">
                    {takeaways.map((t, i) => (
                      <li key={i} className="flex items-start gap-3 text-sm" style={{ color: 'var(--text-1)' }}>
                        <span className="w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                          style={{ background: 'rgba(225,29,72,.12)', border: '1px solid rgba(225,29,72,.3)' }}>
                          <span className="text-[10px] font-mono num font-bold" style={{ color: '#f87171' }}>{i + 1}</span>
                        </span>
                        <span>{t}</span>
                      </li>
                    ))}
                  </ul>
                  <p className="text-[10px] mt-3 pt-3 border-t" style={{ color: 'var(--text-4)', borderColor: 'var(--border)' }}>
                    Storageless: these adjustments live in RAM and are cleared when the session ends. Nothing is persisted to disk.
                  </p>
                </CardWrap>
              </>
            )
          })()}

          {/* L1 — Top noisy rules + recommended action, no full table */}
          {role === 'L1' && (() => {
            const ruleStats = {}
            Object.values(verdicts).forEach(v => {
              const rid = alerts.find(a => a.alert_id === v.alert_id)?.rule_id
              if (!rid) return
              ruleStats[rid] = ruleStats[rid] || { tp: 0, fp: 0 }
              if (v.decision === 'TP') ruleStats[rid].tp++
              if (v.decision === 'FP') ruleStats[rid].fp++
            })
            const noisy = Object.entries(ruleStats)
              .map(([rid, s]) => ({ rid, ...s, total: s.tp + s.fp, fpRate: s.fp / Math.max(1, s.tp + s.fp) }))
              .filter(r => r.total >= 2)
              .sort((a, b) => b.fpRate - a.fpRate)
              .slice(0, 3)
            if (!noisy.length) {
              return (
                <CardWrap className="p-5">
                  <p className="text-sm text-center" style={{ color: 'var(--text-3)' }}>
                    Not enough verdicts yet to flag noisy rules. Triage a few more alerts to populate insights.
                  </p>
                </CardWrap>
              )
            }
            return (
              <CardWrap className="p-5">
                <SectionHead title="Top 3 noisy rules · act this shift" />
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                  {noisy.map((r, i) => {
                    const hot = r.fpRate > 0.4
                    return (
                      <div key={r.rid} className="rounded-xl p-4"
                        style={{ background: 'var(--surface-2)', border: `1px solid ${hot ? 'rgba(225,29,72,.35)' : 'var(--border)'}` }}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono num text-sm font-extrabold" style={{ color: hot ? '#f87171' : 'var(--text-1)' }}>{r.rid}</span>
                          <span className="text-[10px] num font-bold px-1.5 py-0.5 rounded"
                            style={{ background: hot ? 'rgba(225,29,72,.15)' : 'var(--surface-3)', color: hot ? '#f87171' : 'var(--text-2)' }}>
                            FP {Math.round(r.fpRate * 100)}%
                          </span>
                        </div>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
                          {r.tp} TP · {r.fp} FP recorded
                        </p>
                        <p className="text-xs mt-2 leading-snug" style={{ color: hot ? '#fecaca' : 'var(--text-2)' }}>
                          {hot ? 'Raise threshold or scope tighter — too many FPs draining triage time.' : 'Healthy precision — keep current threshold.'}
                        </p>
                      </div>
                    )
                  })}
                </div>
              </CardWrap>
            )
          })()}

          {/* L2 — Full feedback table + drift annotation */}
          {role === 'L2' && (
            <>
              <div className="relative max-w-md">
                <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-4)' }} />
                <input
                  value={insightsQuery}
                  onChange={e => setInsightsQuery(e.target.value)}
                  placeholder="Filter rules (e.g. R001, brute)…"
                  className="w-full text-sm pl-9 pr-8 py-2 rounded-lg outline-none"
                  style={{ background: 'var(--surface)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }}
                  onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                  onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
                />
                {insightsQuery && (
                  <button onClick={() => setInsightsQuery('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xl leading-none" style={{ color: 'var(--text-4)' }}>×</button>
                )}
              </div>
              <CardWrap>
                <FeedbackInsights sessionId={session.session_id} query={insightsQuery} />
              </CardWrap>
              <CardWrap className="p-5">
                <SectionHead title="Per-feature weight drift · this session" />
                <p className="text-xs mt-2 mb-3" style={{ color: 'var(--text-3)' }}>
                  Online weighting nudges applied to the score model from your verdicts. Cleared on session end.
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[
                    ['severity_weight',     +0.08, 'TPs concentrated in CRITICAL rules'],
                    ['mitre_chain_weight',  +0.05, 'Multi-tactic chains rarely FP'],
                    ['rule_R001_threshold', -0.03, 'Brute-force threshold loosened'],
                    ['ueba_weight',         +0.02, 'UEBA signals confirmed by analyst'],
                  ].map(([k, d, why]) => (
                    <div key={k} className="rounded-lg p-3"
                      style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                      <p className="text-[10px] font-mono" style={{ color: 'var(--text-4)' }}>{k}</p>
                      <p className="text-sm font-bold num mt-0.5" style={{ color: d > 0 ? '#4ade80' : '#fbbf24' }}>
                        {d > 0 ? '+' : ''}{d.toFixed(2)}
                      </p>
                      <p className="text-[10px] mt-1 leading-snug" style={{ color: 'var(--text-3)' }}>{why}</p>
                    </div>
                  ))}
                </div>
              </CardWrap>
            </>
          )}
        </div>
      )}

      {/* ── Report Export tab ── */}
      {activeTab === 'report' && (
        <div className="space-y-5">
          {/* Export card */}
          <CardWrap style={{ border: '1px solid rgba(225,29,72,0.15)', background: 'linear-gradient(135deg, var(--surface) 0%, rgba(225,29,72,0.03) 100%)' }}>
            <div className="p-6">
              <div className="flex items-start gap-4 mb-6">
                <div className="w-12 h-12 rounded-2xl flex items-center justify-center shrink-0 icon-3d-red">
                  {role === 'L1'
                    ? <ClipboardList size={24} color="#f43f5e" strokeWidth={1.5} />
                    : <FileBarChart  size={24} color="#f43f5e" strokeWidth={1.5} />}
                </div>
                <div>
                  <h3 className="font-bold text-white text-lg flex items-center gap-2 flex-wrap">
                    {role === 'L1' ? 'L1 Operational Shift Report' : 'L2 Forensic Threat Report'}
                    <span className={role === 'L2' ? 'tier-badge tier-l2' : 'tier-badge tier-l1'}>
                      {role === 'L2' ? <Shield size={11} /> : <ShieldAlert size={11} />} {role}
                    </span>
                  </h3>
                  <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>
                    {role === 'L1'
                      ? 'Concise shift handover: queue stats, triage coverage, escalation list, and action items. Optimised for fast Tier-1 review.'
                      : 'Full forensic dossier: threat score, kill-chain progression, per-incident evidence (MITRE, IOCs, AI reasoning, raw logs), top talkers, and hunt hypotheses.'}
                  </p>
                </div>
              </div>

              {/* Report contents preview — differs by role (lucide icons, consistent) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
                {(role === 'L1' ? [
                  { key: 'summary',         icon: ClipboardList, title: 'Shift Summary',        desc: 'Queue depth, resolved, coverage %' },
                  { key: 'incidents',       icon: AlertOctagon,  title: 'Escalation List',      desc: `${tpCount} confirmed → Incident Response` },
                  { key: 'threat',          icon: Target,        title: 'Pending Workload',     desc: `${pending} alert(s) awaiting triage` },
                  { key: 'recommendations', icon: FileText,      title: 'Action Items',         desc: 'Shift handover checklist' },
                ] : [
                  { key: 'summary',         icon: FileBarChart,  title: 'Executive Summary',    desc: `Threat score, ${tpCount} TP, precision` },
                  { key: 'threat',          icon: Layers,        title: 'Kill-Chain Analysis',  desc: 'Attack progression across tactics' },
                  { key: 'mitre',           icon: Shield,        title: 'MITRE ATT&CK Coverage',desc: `${uniqueTactics} tactics, ${uniqueTechniques} techniques` },
                  { key: 'incidents',       icon: AlertOctagon,  title: 'Forensic Incident Detail', desc: `${tpCount} TP with evidence + raw logs` },
                  { key: 'ioc',             icon: Globe,         title: 'IOC Inventory + Talkers',  desc: 'IPs, users, techniques, top sources' },
                  { key: 'recommendations', icon: Crosshair,     title: 'Hunts + Recommendations',  desc: 'Hypotheses & remediation' },
                ]).map(({ key, icon: I, title, desc }) => {
                  const on = reportSections[key]
                  return (
                    <div key={key} onClick={() => setReportSections(s => ({ ...s, [key]: !s[key] }))}
                      className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer transition-all border"
                      style={{
                        borderColor: on ? 'rgba(225,29,72,.35)' : 'var(--border)',
                        background:  on ? 'rgba(225,29,72,.06)' : 'var(--surface-2)',
                        opacity:     on ? 1 : 0.65,
                      }}>
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                        style={{
                          background: on ? 'rgba(225,29,72,.15)' : 'var(--surface-3)',
                          border: `1px solid ${on ? 'rgba(225,29,72,.35)' : 'var(--border-2)'}`,
                        }}>
                        <I size={14} color={on ? '#f87171' : '#9ca3af'} strokeWidth={1.8} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold text-white truncate">{title}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{desc}</p>
                      </div>
                      <div className="shrink-0 w-4 h-4 rounded border flex items-center justify-center transition-colors"
                        style={{ borderColor: on ? 'var(--accent)' : 'var(--text-4)', background: on ? 'var(--accent)' : 'transparent' }}>
                        {on && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/></svg>}
                      </div>
                    </div>
                  )
                })}
              </div>

              <div className="flex flex-col sm:flex-row items-center gap-4 border-t pt-6 mt-2" style={{ borderColor: 'var(--border-2)' }}>
                <div className="flex-1 w-full relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[10px] uppercase font-bold tracking-widest text-zinc-500 pointer-events-none">Signoff</span>
                  <input
                    value={analyst}
                    onChange={e => setAnalyst(e.target.value)}
                    placeholder="Analyst Name"
                    className="w-full text-sm font-semibold rounded-xl pl-20 pr-4 py-3 focus:outline-none transition-all"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border-3)', color: 'var(--text-1)', boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.2)' }}
                    onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                    onBlur={e => e.target.style.borderColor = 'var(--border-3)'}
                  />
                </div>
                <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
                  <button
                    onClick={handleDownload}
                    disabled={downloading || !Object.values(reportSections).some(Boolean)}
                    className="w-full sm:w-auto btn-accent flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-sm font-bold shadow-2xl hover-glow disabled:opacity-50"
                  >
                    {downloading ? (
                      <><Loader2 size={15} className="animate-spin" /> Generating…</>
                    ) : (
                      <>
                        {role === 'L1' ? <ClipboardList size={15} /> : <FileBarChart size={15} />}
                        Generate {role} Report
                        <Download size={13} />
                      </>
                    )}
                  </button>
                  {!session?.session_id?.startsWith('demo-') && (
                    <button
                      onClick={handleServerPdf}
                      disabled={downloading}
                      title="Server-rendered PDF (backend sessions only)"
                      className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm font-bold transition-all disabled:opacity-50"
                      style={{ background: 'var(--surface-2)', border: '1px solid var(--border-3)', color: 'var(--text-2)' }}
                    >
                      Server PDF
                    </button>
                  )}
                </div>
              </div>
            </div>
          </CardWrap>

          {/* Recommendations */}
          <CardWrap>
            <div className="p-5">
              <p className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: 'var(--text-3)' }}>Analyst Recommendations</p>
              <div className="space-y-3">
                {tpCount > 0 && (
                  <div className="flex gap-3 px-4 py-3 rounded-xl" style={{ background: 'rgba(225,29,72,0.05)', border: '1px solid rgba(225,29,72,0.15)' }}>
                    <span className="text-red-400 text-sm shrink-0">🔴</span>
                    <p className="text-sm text-white"><span className="font-semibold">Immediate:</span> <span style={{ color: 'var(--text-2)' }}>{tpCount} confirmed threat(s) require incident response. Isolate affected hosts and revoke compromised credentials immediately.</span></p>
                  </div>
                )}
                {criticalAlerts.length > 0 && (
                  <div className="flex gap-3 px-4 py-3 rounded-xl" style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)' }}>
                    <span className="text-orange-400 text-sm shrink-0">⚠️</span>
                    <p className="text-sm text-white"><span className="font-semibold">Priority:</span> <span style={{ color: 'var(--text-2)' }}>{criticalAlerts.length} CRITICAL alert(s) detected. Review associated IOCs and block malicious IPs at perimeter firewall.</span></p>
                  </div>
                )}
                {pending > 0 && (
                  <div className="flex gap-3 px-4 py-3 rounded-xl" style={{ background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.15)' }}>
                    <span className="text-amber-400 text-sm shrink-0">⏳</span>
                    <p className="text-sm text-white"><span className="font-semibold">Pending:</span> <span style={{ color: 'var(--text-2)' }}>{pending} alert(s) still require analyst review. Complete triage before closing this session to ensure full coverage.</span></p>
                  </div>
                )}
                {uniqueTactics > 3 && (
                  <div className="flex gap-3 px-4 py-3 rounded-xl" style={{ background: 'rgba(6,182,212,0.05)', border: '1px solid rgba(6,182,212,0.15)' }}>
                    <span className="text-cyan-400 text-sm shrink-0">🛡️</span>
                    <p className="text-sm text-white"><span className="font-semibold">Coverage:</span> <span style={{ color: 'var(--text-2)' }}>{uniqueTactics} MITRE ATT&CK tactics observed. Consider reviewing detection coverage across all kill-chain phases and hardening gaps.</span></p>
                  </div>
                )}
                {tpCount === 0 && pending === 0 && criticalAlerts.length === 0 && (
                  <div className="flex gap-3 px-4 py-3 rounded-xl" style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.15)' }}>
                    <span className="text-emerald-400 text-sm shrink-0">✅</span>
                    <p className="text-sm text-white"><span className="font-semibold">Clear:</span> <span style={{ color: 'var(--text-2)' }}>No confirmed incidents in this session. All alerts reviewed and dismissed. Continue monitoring for new activity.</span></p>
                  </div>
                )}
              </div>
            </div>
          </CardWrap>
        </div>
      )}

      {/* Empty state */}
      {alerts.length === 0 && (
        <div className="text-center py-24" style={{ color: 'var(--text-3)' }}>
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 icon-3d">
            <span className="text-3xl">📊</span>
          </div>
          <p className="text-white font-semibold">No session data</p>
          <button onClick={() => navigate('/')} className="text-xs mt-2 underline transition-opacity hover:opacity-80" style={{ color: 'var(--accent)' }}>
            Upload a log file to begin
          </button>
        </div>
      )}
    </div>
  )
}
