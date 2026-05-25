import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  ArrowLeft, Bot, Clock, Globe, ShieldAlert, Network,
  BarChart3, Activity, Share2, Layers, Crosshair,
  ShieldCheck, Loader2,
} from 'lucide-react'
import { investigate, threatIntel, getPlaybook, submitVerdict, getAlertGraph, getGraph } from '../api/client'
import { useSession } from '../App'
import ShapChart from '../components/ShapChart'
import BehaviorProfile from '../components/BehaviorProfile'
import ChainCard from '../components/ChainCard'
import AssetCard from '../components/AssetCard'
import GraphView from '../components/GraphView'
import AIAgentPanel from '../components/AIAgentPanel'
import ChainNarrative from '../components/ChainNarrative'

const SEV_CLASS = {
  CRITICAL: 'sev-chip sev-chip-critical',
  HIGH:     'sev-chip sev-chip-high',
  MEDIUM:   'sev-chip sev-chip-medium',
  LOW:      'sev-chip sev-chip-low',
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { text: 'text-red-500',    bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)' },
  HIGH:     { text: 'text-red-400',    bg: 'rgba(244,63,94,0.08)',   border: 'rgba(244,63,94,0.25)' },
  MEDIUM:   { text: 'text-red-300',    bg: 'rgba(225,29,72,0.08)',   border: 'rgba(225,29,72,0.25)' },
  LOW:      { text: 'text-zinc-400',   bg: 'rgba(113,113,122,0.08)', border: 'rgba(113,113,122,0.25)' },
}

const PHASE_COLOUR = {
  Immediate: 'rgba(225,29,72,0.12)',    Contain:   'rgba(244,63,94,0.12)',
  Investigate:'rgba(159,18,57,0.12)',   Assess:    'rgba(225,29,72,0.12)',
  Remediate: 'rgba(239,68,68,0.12)',    Harden:    'rgba(248,113,113,0.12)',
  Report:    'rgba(113,113,122,0.12)',  'Legal/Compliance':'rgba(161,161,170,0.12)',
  Confirm:   'rgba(159,18,57,0.12)',
}
const PHASE_TEXT = {
  Immediate: '#f87171',   Contain:   '#fb7185',
  Investigate:'#f43f5e',  Assess:    '#e11d48',
  Remediate: '#ef4444',   Harden:    '#fca5a5',
  Report:    '#a1a1aa',   'Legal/Compliance':'#d4d4d8',
  Confirm:   '#fda4af',
}

// Attack Knowledge — derives kill-chain stage, likely objective, and recommended pivots
// from the alert's MITRE mapping + rule. Gives the analyst real attacker context, not just a score.
const KILLCHAIN_STAGE = {
  'Initial Access':      { stage: 'Stage 1 · Foothold',        objective: 'Establish presence on a target system.', pivots: ['Search for the same source IP across other hosts', 'Pivot to user-account auth events ± 1h', 'Check for follow-on execution within 15 min'] },
  'Execution':           { stage: 'Stage 2 · Code Execution',  objective: 'Run attacker-controlled code to advance.', pivots: ['Hunt process-tree children of the parent', 'Look for downloaded binaries on the host', 'Check for scheduled-task / service creation'] },
  'Persistence':         { stage: 'Stage 3 · Persistence',     objective: 'Survive reboots and credential rotations.', pivots: ['Enumerate run keys / cron / service installs on host', 'Hunt for the same persistence method elsewhere', 'Audit recently-created accounts'] },
  'Privilege Escalation':{ stage: 'Stage 3 · Privilege Esc.',  objective: 'Gain higher-trust account or process token.', pivots: ['Hunt for token-impersonation events on host', 'Check group membership changes', 'Review sudo / runas usage by the user'] },
  'Defense Evasion':     { stage: 'Stage 4 · Evasion',         objective: 'Avoid detection and clear traces.', pivots: ['Look for event-log clear / disabled AV', 'Hunt for LOLBin process executions', 'Diff host config against baseline'] },
  'Credential Access':   { stage: 'Stage 4 · Credential Theft',objective: 'Harvest credentials for lateral movement.', pivots: ['Pivot to LSASS / credential-store reads on host', 'Hunt for the same user from new hosts in 24h', 'Check for password-spray or impossible-travel'] },
  'Discovery':           { stage: 'Stage 5 · Discovery',       objective: 'Map the environment for next steps.', pivots: ['Hunt for AD enumeration commands by user', 'Look for port-scan patterns from same source', 'Check for network-share enumeration'] },
  'Lateral Movement':    { stage: 'Stage 6 · Lateral Movement',objective: 'Expand foothold to other systems.', pivots: ['Trace RDP / SMB / WMI from source to dest', 'Hunt for service creation on the destination', 'Look for the same credentials reused elsewhere'] },
  'Collection':          { stage: 'Stage 7 · Collection',      objective: 'Stage data for later exfiltration.', pivots: ['Hunt for large reads from file shares', 'Check for archive (zip/rar) creation', 'Look for clipboard / screenshot tooling'] },
  'Command & Control':   { stage: 'Stage 8 · C2',              objective: 'Maintain attacker channel into the network.', pivots: ['Hunt for periodic beaconing patterns', 'Pivot to DNS tunneling / unusual TLS SNI', 'Check destination IP reputation + ASN'] },
  'Exfiltration':        { stage: 'Stage 9 · Exfiltration',    objective: 'Move staged data out of the environment.', pivots: ['Hunt for large outbound transfers', 'Check for cloud-storage uploads from host', 'Look for off-hours data movement'] },
  'Impact':              { stage: 'Stage 10 · Impact',         objective: 'Achieve the attacker\'s end goal (ransom, destruction, theft).', pivots: ['Check for mass file rename / encryption', 'Look for service shutdown / shadow-copy delete', 'Audit account-disable + admin-creation events'] },
}

function AttackKnowledgeCard({ alert, onPivot }) {
  const tactic = alert?.mitre_tactic || 'Initial Access'
  const knowledge = KILLCHAIN_STAGE[tactic] || KILLCHAIN_STAGE['Initial Access']
  return (
    <div className="rounded-2xl p-5 section-zoom"
      style={{ background: 'linear-gradient(135deg, rgba(225,29,72,.08), rgba(159,18,57,.03))', border: '1px solid rgba(225,29,72,.25)' }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Crosshair size={14} color="#f87171" />
          <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: '#f87171' }}>Attack Knowledge</span>
        </div>
        <span className="text-[10px] font-mono num px-2 py-0.5 rounded"
          style={{ background: 'rgba(225,29,72,.12)', border: '1px solid rgba(225,29,72,.3)', color: '#f87171' }}>
          {knowledge.stage}
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>Attacker objective</p>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--text-1)' }}>{knowledge.objective}</p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <span className="text-[10px] px-2 py-0.5 rounded font-mono num"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
              MITRE {alert?.mitre_technique || '—'}
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded uppercase tracking-wider"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-3)' }}>
              {tactic}
            </span>
          </div>
        </div>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-4)' }}>Recommended pivots</p>
          <ul className="space-y-1.5">
            {knowledge.pivots.map((p, i) => (
              <li key={i} className="flex items-start gap-2 text-xs" style={{ color: 'var(--text-2)' }}>
                <span className="font-mono num text-[10px] mt-0.5 shrink-0" style={{ color: '#f87171' }}>{String(i + 1).padStart(2, '0')}</span>
                <span>{p}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

// Trustable scoring panel: shows the signals that produced the AI confidence.
function AiConfidenceCard({ alert, probPct }) {
  const [open, setOpen] = useState(false)
  const reasons = []
  if (alert?.severity === 'CRITICAL') reasons.push(['+25', 'Critical severity classification'])
  else if (alert?.severity === 'HIGH') reasons.push(['+15', 'High severity classification'])
  const m = alert?.detection_methods || []
  if (m.includes('rule_based'))          reasons.push(['+10', 'Deterministic rule matched threshold'])
  if (m.includes('behavioral_anomaly'))  reasons.push(['+18', 'UEBA baseline deviation (σ > 2)'])
  if (m.includes('pattern_correlation')) reasons.push(['+12', 'Cross-event correlation signal'])
  if (alert?.mitre_techniques?.length > 1)
    reasons.push(['+15', `${alert.mitre_techniques.length} MITRE techniques chained`])
  else if (alert?.mitre_technique)
    reasons.push(['+5', `Mapped to MITRE ${alert.mitre_technique}`])
  if (alert?.anomaly_score != null && alert.anomaly_score > 0.6)
    reasons.push(['+10', `IsolationForest anomaly ${Math.round(alert.anomaly_score*100)}%`])
  if (alert?.event_count > 5)
    reasons.push(['+8', `${alert.event_count} correlated events`])
  if (!reasons.length) reasons.push(['—', 'Baseline rule confidence only'])
  const col = probPct >= 75 ? '#ff0000' : probPct >= 45 ? '#e11d48' : '#6b7280'
  return (
    <div className="rounded-2xl p-4 min-w-[220px] transition-all" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>AI Confidence</p>
        <button onClick={() => setOpen(o => !o)} className="text-[10px] px-1.5 py-0.5 rounded transition-colors"
          style={{ color: open ? '#f87171' : 'var(--text-3)', border: `1px solid ${open ? 'rgba(225,29,72,.35)' : 'var(--border-2)'}` }}>
          {open ? 'Hide' : 'Why?'}
        </button>
      </div>
      <p className="text-center text-3xl font-extrabold tabular-nums" style={{ color: col }}>{probPct}%</p>
      <div className="mt-2 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
        <div className="h-full rounded-full" style={{ width: `${probPct}%`, background: probPct >= 75 ? 'linear-gradient(90deg,#9f1239,#ff0000)' : probPct >= 45 ? 'linear-gradient(90deg,#9f1239,#e11d48)' : 'linear-gradient(90deg,#3d3d48,#6b7280)' }} />
      </div>
      <p className="text-[10px] mt-1 text-center" style={{ color: 'var(--text-4)' }}>TP probability · click "Why?" for signals</p>
      {open && (
        <div className="mt-3 pt-3 space-y-1.5 border-t fade-in" style={{ borderColor: 'var(--border)' }}>
          <p className="text-[10px]" style={{ color: 'var(--text-3)' }}>
            Composite of <span style={{ color: 'var(--text-1)' }}>deterministic rules</span>, <span style={{ color: 'var(--text-1)' }}>UEBA</span>, and <span style={{ color: 'var(--text-1)' }}>AI re-scoring</span>. Each signal listed below contributed weight to the final score.
          </p>
          <ul className="space-y-1 mt-2">
            {reasons.map(([w, txt], i) => (
              <li key={i} className="flex items-start gap-2 text-xs">
                <span className="font-mono text-[10px] shrink-0 num px-1.5 py-0.5 rounded"
                  style={{ background: 'rgba(225,29,72,.10)', color: '#f87171', minWidth: 36, textAlign: 'center' }}>{w}</span>
                <span style={{ color: 'var(--text-2)' }}>{txt}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }) }}
      className="text-[10px] px-1.5 py-0.5 rounded transition-all"
      style={{ color: copied ? '#4ade80' : 'var(--text-4)', border: '1px solid var(--border)', background: 'var(--surface-2)' }}
    >{copied ? '✓' : '⎘'}</button>
  )
}

function Card({ title, children, action, style = {} }) {
  return (
    <div className="rounded-2xl overflow-hidden section-zoom" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)', ...style }}>
      <div className="flex items-center justify-between px-5 py-3.5 border-b" style={{ borderColor: 'var(--border)' }}>
        <h3 className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{title}</h3>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function EventDetail({ row }) {
  // Azure-Sentinel-style: full key/value breakdown of the selected event.
  const FIELDS = [
    ['Timestamp', row.timestamp ? new Date(row.timestamp).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—'],
    ['Event Type', row.event_type || '—'],
    ['Source IP', row.source_ip || '—'],
    ['Destination IP', row.dest_ip || '—'],
    ['User', row.user || '—'],
    ['Status', row.status || '—'],
    ['Port', row.port != null ? row.port : '—'],
    ['Row Index', row.row_index != null ? row.row_index : '—'],
  ]
  return (
    <div className="mt-2 rounded-lg p-3" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
        {FIELDS.map(([k, v]) => (
          <div key={k} className="flex flex-col">
            <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-4)' }}>{k}</span>
            <span className="text-xs font-mono break-all flex items-center gap-1.5" style={{ color: 'var(--text-1)' }}>
              {String(v)}
              {['Source IP', 'Destination IP', 'User'].includes(k) && v !== '—' && <CopyBtn text={String(v)} />}
            </span>
          </div>
        ))}
      </div>
      {row.raw && (
        <div className="mt-3">
          <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-4)' }}>Raw Event</span>
          <pre className="text-[11px] font-mono mt-1 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all"
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text-2)' }}>{row.raw}</pre>
        </div>
      )}
    </div>
  )
}

function Timeline({ rows }) {
  const [expanded, setExpanded] = useState(false)
  const [openIdx, setOpenIdx] = useState(null)
  if (!rows?.length) return <p className="text-sm" style={{ color: 'var(--text-3)' }}>No related log rows found.</p>

  // Single project theme: suspicious = accent red, everything else = muted.
  const visible = expanded ? rows : rows.slice(0, 8)
  const isOpen = (i) => openIdx === i

  return (
    <div className="space-y-1.5">
      <div className="max-h-[28rem] overflow-y-auto space-y-1.5 pr-1">
        {visible.map((row, i) => {
          const suspicious = row.tone === 'suspicious'
          const open = isOpen(i)
          return (
            <div key={i} className="rounded-lg overflow-hidden transition-colors"
              style={{ border: `1px solid ${open ? 'var(--accent)' : 'var(--border)'}` }}>
              <button
                onClick={() => setOpenIdx(open ? null : i)}
                className="w-full text-left border-l-2 pl-3 pr-2 py-2 transition-colors hover:bg-white/[0.02]"
                style={{ borderLeftColor: suspicious ? 'var(--accent)' : 'var(--border-3)' }}
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <svg className={`w-3 h-3 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-4)' }}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  <span className="font-mono shrink-0" style={{ color: 'var(--text-4)' }}>
                    {row.timestamp ? new Date(row.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '—'}
                  </span>
                  {row.source_ip && <span className="font-mono" style={{ color: 'var(--text-2)' }}>{row.source_ip}</span>}
                  {row.event_type && <span style={{ color: 'var(--text-1)' }}>{row.event_type}</span>}
                  {row.user && <span style={{ color: 'var(--text-2)' }}>{row.user}</span>}
                  {row.status && (
                    <span className="font-bold" style={{ color: suspicious ? 'var(--accent)' : 'var(--text-3)' }}>
                      {row.status}
                    </span>
                  )}
                  {row.port != null && <span style={{ color: 'var(--text-4)' }}>:{row.port}</span>}
                </div>
                {!open && row.raw && (
                  <p className="text-[10px] font-mono mt-0.5 truncate pl-5" style={{ color: 'var(--text-4)' }}>{row.raw}</p>
                )}
              </button>
              {open && <div className="px-3 pb-3"><EventDetail row={row} /></div>}
            </div>
          )
        })}
      </div>
      {rows.length > 8 && (
        <button onClick={() => setExpanded(e => !e)} className="text-xs transition-colors" style={{ color: 'var(--accent)' }}>
          {expanded ? '↑ Show less' : `↓ Show all ${rows.length} events`}
        </button>
      )}
    </div>
  )
}

// ── IOCs ──────────────────────────────────────────────────────────────────────
function IOCs({ iocs, sessionId, onIntelLoaded }) {
  const [querying, setQuerying] = useState({})
  const [results,  setResults]  = useState({})

  const query = async (ip) => {
    if (querying[ip] || results[ip]) return
    setQuerying(q => ({ ...q, [ip]: true }))
    try {
      const { data } = await threatIntel(sessionId, ip)
      setResults(r => ({ ...r, [ip]: data }))
      onIntelLoaded?.(data)
    } catch (err) {
      toast.error(`Threat intel failed: ${err.response?.data?.detail || err.message}`)
    } finally { setQuerying(q => ({ ...q, [ip]: false })) }
  }

  const VerdictPill = ({ verdict }) => {
    if (!verdict) return null
    const c = { malicious: ['rgba(225,29,72,0.15)','rgba(225,29,72,0.3)','#f87171'], suspicious: ['rgba(244,63,94,0.15)','rgba(244,63,94,0.3)','#fb7185'], clean: ['rgba(107,114,128,0.15)','rgba(107,114,128,0.3)','#9ca3af'] }[verdict.label] || ['var(--surface-3)','var(--border-2)','var(--text-2)']
    return <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold" style={{ background: c[0], border: `1px solid ${c[1]}`, color: c[2] }}>{verdict.label}</span>
  }

  const IocSection = ({ title, children }) => (
    <div>
      <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: 'var(--text-4)' }}>{title}</p>
      {children}
    </div>
  )

  const hasAny = iocs.ips?.length || iocs.users?.length || iocs.ports?.length || iocs.domains?.length || iocs.hashes?.length

  return (
    <div className="space-y-4">
      {iocs.ips?.length > 0 && (
        <IocSection title={`IP Addresses (${iocs.ips.length})`}>
          <div className="space-y-1.5">
            {iocs.ips.map(ip => (
              <div key={ip} className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <span className="text-xs font-mono flex-1 text-white">{ip}</span>
                <CopyBtn text={ip} />
                {results[ip]
                  ? <VerdictPill verdict={results[ip].verdict} />
                  : <button onClick={() => query(ip)} disabled={querying[ip]}
                      className="text-xs px-2 py-0.5 rounded transition-all disabled:opacity-50"
                      style={{ color: 'var(--accent)', border: '1px solid rgba(225,29,72,0.25)', background: 'rgba(225,29,72,0.06)' }}>
                      {querying[ip] ? <span className="inline-block w-3 h-3 border border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--accent)', borderTopColor: 'transparent' }} /> : 'Lookup →'}
                    </button>
                }
              </div>
            ))}
          </div>
        </IocSection>
      )}

      {iocs.users?.length > 0 && (
        <IocSection title={`Users (${iocs.users.length})`}>
          <div className="flex flex-wrap gap-2">
            {iocs.users.map(u => (
              <div key={u} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <span style={{ color: '#fca5a5' }}>👤</span> {u} <CopyBtn text={u} />
              </div>
            ))}
          </div>
        </IocSection>
      )}

      {iocs.ports?.length > 0 && (
        <IocSection title="Ports">
          <div className="flex flex-wrap gap-1.5">
            {iocs.ports.map(p => (
              <span key={p} className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>:{p}</span>
            ))}
          </div>
        </IocSection>
      )}

      {iocs.domains?.length > 0 && (
        <IocSection title={`Domains (${Math.min(iocs.domains.length, 20)})`}>
          <div className="flex flex-wrap gap-1.5">
            {iocs.domains.slice(0, 20).map(d => (
              <div key={d} className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono"
                style={{ background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.2)', color: '#fb7185' }}>
                {d} <CopyBtn text={d} />
              </div>
            ))}
          </div>
        </IocSection>
      )}

      {iocs.hashes?.length > 0 && (
        <IocSection title="Hashes">
          <div className="space-y-1">
            {iocs.hashes.slice(0, 10).map(h => (
              <div key={h} className="flex items-center gap-2 px-3 py-1.5 rounded-lg" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <span className="text-[10px] font-mono flex-1 truncate" style={{ color: 'var(--text-3)' }}>{h}</span>
                <CopyBtn text={h} />
              </div>
            ))}
          </div>
        </IocSection>
      )}

      {!hasAny && <p className="text-sm" style={{ color: 'var(--text-3)' }}>No IOCs extracted from related log rows.</p>}
    </div>
  )
}

// ── Threat Intel Card ─────────────────────────────────────────────────────────
function IntelCard({ ip, data }) {
  const { abuseipdb: ab, virustotal: vt, verdict } = data
  const VC = { malicious: '#f87171', suspicious: '#fb7185', clean: '#9ca3af' }
  return (
    <div className="rounded-xl p-4 space-y-3" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-white">{ip}</span>
          <CopyBtn text={ip} />
        </div>
        <span className="text-xs font-extrabold uppercase" style={{ color: VC[verdict?.label] || 'var(--text-3)' }}>{verdict?.label || '—'}</span>
      </div>
      {verdict?.rationale?.length > 0 && (
        <ul className="text-xs space-y-1" style={{ color: 'var(--text-2)' }}>
          {verdict.rationale.map((r,i) => <li key={i} className="flex gap-1.5"><span style={{ color: 'var(--text-4)' }}>•</span>{r}</li>)}
        </ul>
      )}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        {ab?.available && <>
          <span style={{ color: 'var(--text-3)' }}>AbuseIPDB Score</span>
          <span className="font-bold" style={{ color: (ab.abuse_confidence_score??0)>50?'#f87171':'var(--text-1)' }}>{ab.abuse_confidence_score??'—'}/100 · {ab.total_reports??0} reports</span>
          {ab.country_code && <><span style={{ color: 'var(--text-3)' }}>Country</span><span className="text-white">{ab.country_code}</span></>}
          {ab.isp && <><span style={{ color: 'var(--text-3)' }}>ISP</span><span className="text-white truncate">{ab.isp}</span></>}
        </>}
        {vt?.available && <>
          <span style={{ color: 'var(--text-3)' }}>VT Malicious</span>
          <span className="font-bold" style={{ color: (vt.stats?.malicious??0)>0?'#f87171':'#9ca3af' }}>{vt.stats?.malicious??0} vendors</span>
          {vt.country && <><span style={{ color: 'var(--text-3)' }}>Country</span><span className="text-white">{vt.country}</span></>}
          {vt.as_owner && <><span style={{ color: 'var(--text-3)' }}>AS Owner</span><span className="text-white truncate">{vt.as_owner}</span></>}
        </>}
      </div>
      {data._cache_hit && <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>⚡ cached result</p>}
    </div>
  )
}

// ── Playbook ──────────────────────────────────────────────────────────────────
function PlaybookPanel({ ruleId }) {
  const [playbook, setPlaybook] = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [checked,  setChecked]  = useState(new Set())

  useEffect(() => {
    getPlaybook(ruleId).then(({ data }) => setPlaybook(data)).catch(() => setPlaybook(null)).finally(() => setLoading(false))
  }, [ruleId])

  if (loading) return (
    <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-3)' }}>
      <span className="w-4 h-4 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--accent)', borderTopColor: 'transparent' }} />
      Loading playbook…
    </div>
  )
  if (!playbook) return <p className="text-sm" style={{ color: 'var(--text-3)' }}>No playbook found for {ruleId}.</p>

  const done = checked.size

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="font-bold text-white">{playbook.title}</p>
        <span className="text-xs" style={{ color: 'var(--text-3)' }}>{done}/{playbook.steps.length}</span>
      </div>
      {playbook.steps.length > 0 && (
        <div className="h-1 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(done / playbook.steps.length) * 100}%`, background: 'linear-gradient(90deg,#9ca3af,#d1d5db)' }} />
        </div>
      )}
      <div className="space-y-2">
        {playbook.steps.map(step => {
          const isDone = checked.has(step.step)
          return (
            <div key={step.step}
              onClick={() => setChecked(s => { const n = new Set(s); n.has(step.step) ? n.delete(step.step) : n.add(step.step); return n })}
              className="flex gap-3 px-3 py-2.5 rounded-xl cursor-pointer transition-all"
              style={{ background: isDone ? 'rgba(107,114,128,0.05)' : 'var(--surface-2)', opacity: isDone ? 0.55 : 1 }}
            >
              <div className="w-6 h-6 rounded-full border-2 shrink-0 flex items-center justify-center text-xs font-bold transition-all"
                style={{
                  borderColor: isDone ? '#22c55e' : 'var(--border-3)',
                  background: isDone ? 'rgba(34,197,94,0.15)' : 'transparent',
                  color: isDone ? '#4ade80' : 'var(--text-3)',
                }}>
                {isDone ? '✓' : step.step}
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-[10px] px-2 py-0.5 rounded-full mr-2 font-semibold"
                  style={{ background: PHASE_COLOUR[step.phase] || 'var(--surface-3)', color: PHASE_TEXT[step.phase] || 'var(--text-2)' }}>
                  {step.phase}
                </span>
                <span className="text-sm" style={{ color: isDone ? 'var(--text-4)' : 'var(--text-1)', textDecoration: isDone ? 'line-through' : 'none' }}>
                  {step.action}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Entities sidebar ──────────────────────────────────────────────────────────
function Entities({ entities }) {
  return (
    <div className="space-y-4">
      {entities?.ips?.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: 'var(--text-4)' }}>IP Entities</p>
          <div className="space-y-1.5">
            {entities.ips.slice(0, 6).map(e => (
              <div key={e.ip} className="px-3 py-2.5 rounded-xl text-xs space-y-1" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-bold text-white truncate">{e.ip}</span>
                  <CopyBtn text={e.ip} />
                </div>
                <div className="flex flex-wrap gap-2" style={{ color: 'var(--text-3)' }}>
                  <span>{e.events} events</span>
                  {e.roles?.map(r => <span key={r} className="px-1.5 py-0.5 rounded text-[10px]" style={{ background: 'var(--surface-3)' }}>{r}</span>)}
                </div>
                {e.first_seen && (
                  <p className="text-[10px] font-mono" style={{ color: 'var(--text-4)' }}>
                    {new Date(e.first_seen).toISOString().slice(0,16).replace('T',' ')} → {new Date(e.last_seen).toISOString().slice(0,16).replace('T',' ')}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {entities?.users?.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: 'var(--text-4)' }}>User Entities</p>
          <div className="space-y-1.5">
            {entities.users.slice(0, 6).map(u => (
              <div key={u.user} className="px-3 py-2.5 rounded-xl text-xs" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span style={{ color: '#fca5a5' }}>👤</span>
                  <span className="font-bold" style={{ color: '#fecaca' }}>{u.user}</span>
                  <CopyBtn text={u.user} />
                </div>
                <div className="flex gap-3" style={{ color: 'var(--text-3)' }}>
                  <span>{u.events} events</span>
                  {u.failures > 0 && <span className="font-bold text-red-400">{u.failures} failures</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function Investigation() {
  const { alertId }  = useParams()
  const { session, setSession } = useSession()
  const navigate     = useNavigate()

  const [data,         setData]       = useState(null)
  const [loading,      setLoading]    = useState(true)
  const [intelResults, setIntel]      = useState([])
  const [activeTab,    setActiveTab]  = useState('timeline')
  const [verdict,      setVerdict]    = useState(null)
  const [submitting,   setSubmitting] = useState(false)

  useEffect(() => {
    if (!session) return

    // Build investigation data locally from the in-memory session.
    // Used for demo sessions (no backend record) and as a graceful fallback
    // when the backend session has expired — so the user always reaches the
    // in-depth analysis instead of being bounced back to the triage queue.
    const buildLocal = () => {
      const a = (session.alerts ?? []).find(x => x.alert_id === alertId)
      if (!a) return null
      const norm = {
        ...a,
        mitre_technique: a.mitre_techniques?.[0] || a.mitre_technique || '—',
        mitre_tactic:    a.mitre_tactics?.[0]   || a.mitre_tactic   || '—',
        tp_probability:  a.tp_probability != null ? a.tp_probability
                         : a.ai_score != null ? a.ai_score / 100 : null,
        ai_explanation:  a.ai_explanation || a.ai_rationale || '',
        event_count:     a.event_count ?? 1,
      }
      const rawLines = a.raw_log ? String(a.raw_log).split('\\n').filter(Boolean) : []
      const timeline = rawLines.map((line, i) => ({
        timestamp: a.timestamp || new Date().toISOString(),
        source_ip: a.source_ip,
        event_type: i === 0 ? a.rule_name : 'evidence',
        user: a.user,
        status: /fail|denied|error/i.test(line) ? 'FAILED' : null,
        raw: line,
        tone: i === 0 ? 'suspicious' : 'info',
      }))
      const ips = [...new Set([a.source_ip, a.dest_ip].filter(Boolean))]
      const users = a.user ? String(a.user).split(',').map(u => u.trim()).filter(Boolean) : []
      return {
        alert: norm,
        related_count: timeline.length,
        timeline,
        iocs: { ips, users, ports: [], domains: [], hashes: [] },
        entities: {
          ips: ips.map(ip => ({
            ip, events: norm.event_count,
            roles: [ip === a.source_ip ? 'source' : 'destination'],
            first_seen: a.timestamp, last_seen: a.timestamp,
          })),
          users: users.map(u => ({ user: u, events: norm.event_count, failures: 0 })),
        },
      }
    }

    const useLocal = () => {
      const local = buildLocal()
      if (local) {
        setData(local)
        if (session.verdicts?.[alertId]) setVerdict(session.verdicts[alertId])
      } else {
        toast.error('Alert not found in this session')
        navigate('/triage')
      }
      setLoading(false)
    }

    // Demo / client-only sessions never hit the backend.
    if (session.session_id?.startsWith('demo-')) { useLocal(); return }

    investigate(session.session_id, alertId)
      .then(({ data: d }) => {
        setData(d)
        if (session.verdicts?.[alertId]) setVerdict(session.verdicts[alertId])
        setLoading(false)
      })
      .catch(() => {
        // Backend session expired / unreachable — fall back to local analysis
        useLocal()
      })
  }, [session, alertId])

  useEffect(() => {
    const sid = session?.session_id
    if (!sid || sid.startsWith('demo-')) {
      setData(prev => prev ? { ...prev, graph: { nodes: [], edges: [] } } : prev)
      return
    }
    let alive = true
    getAlertGraph(sid, alertId)
      .then(async ({ data: g }) => {
        // If the alert subgraph is empty, fall back to the full session graph
        if (!g?.nodes?.length) {
          try {
            const { data: full } = await getGraph(sid)
            return full
          } catch { return g || { nodes: [], edges: [] } }
        }
        return g
      })
      .then(g => { if (alive) setData(prev => prev ? { ...prev, graph: g } : prev) })
      .catch(() => { if (alive) setData(prev => prev ? { ...prev, graph: { nodes: [], edges: [] } } : prev) })
    return () => { alive = false }
  }, [alertId, session?.session_id, data?.alert?.alert_id])

  const handleIntelLoaded = useCallback((result) => {
    setIntel(prev => prev.find(r => r.ip === result.ip) ? prev : [...prev, result])
  }, [])

  const submitVerdictAction = async (decision) => {
    if (submitting || verdict) return
    setSubmitting(true)
    try {
      await submitVerdict({ alert_id: alertId, decision, session_id: session.session_id })
      const v = { alert_id: alertId, decision }
      setVerdict(v)
      setSession(s => ({ ...s, verdicts: { ...(s.verdicts ?? {}), [alertId]: v } }))
      toast.success(decision === 'TP' ? '🔴 Confirmed as True Positive' : '✅ Dismissed as False Positive')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to submit verdict')
    } finally { setSubmitting(false) }
  }

  if (loading) return (
    <div className="flex items-center justify-center py-32 gap-3" style={{ color: 'var(--text-3)' }}>
      <Loader2 size={20} className="animate-spin" color="#f43f5e" />
      Loading investigation data…
    </div>
  )
  if (!data) return null

  const { alert, timeline, iocs, entities } = data
  const sev    = SEV[alert.severity] || SEV.LOW
  const probPct = alert.tp_probability != null ? Math.round(alert.tp_probability * 100) : null

  const goPivot = (filters) => {
    if (!filters?.length) return
    setSession(s => ({ ...s, pendingHuntFilters: filters }))
    navigate('/hunt')
  }

  const TABS = [
    { key: 'agent',    label: 'AI Agent',      icon: Bot },
    { key: 'timeline', label: 'Timeline',      icon: Clock,        count: data.related_count },
    { key: 'iocs',     label: 'IOCs',          icon: Globe,        count: (iocs.ips?.length ?? 0) + (iocs.users?.length ?? 0) + (iocs.hashes?.length ?? 0) },
    { key: 'intel',    label: 'Threat Intel',  icon: ShieldAlert,  count: intelResults.length || null },
    { key: 'playbook', label: 'Playbook',      icon: ShieldCheck },
    { key: 'entities', label: 'Entities',      icon: Network,      count: (entities?.ips?.length ?? 0) + (entities?.users?.length ?? 0) },
    { key: 'shap',     label: 'AI Features',   icon: BarChart3 },
    { key: 'behavior', label: 'Behavior',      icon: Activity },
    { key: 'graph',    label: 'Entity Graph',  icon: Share2 },
    { key: 'chains',   label: 'Attack Chains', icon: Layers },
  ]

  return (
    <div className="space-y-5 fade-in">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <button onClick={() => navigate('/triage')} className="flex items-center gap-1.5 text-xs mb-3 transition-colors" style={{ color: 'var(--text-3)' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--text-1)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-3)'}
          >
            <ArrowLeft size={12} /> Back to Triage Queue
          </button>
          <span className="eyebrow-display mb-3">INVESTIGATION</span>
          <div className="flex items-center gap-2 mt-3 mb-2">
            <span className={SEV_CLASS[alert.severity] || SEV_CLASS.LOW}>{alert.severity}</span>
            <span className="font-mono text-xs num" style={{ color: 'var(--text-3)' }}>{alert.rule_id}</span>
          </div>
          <h1 className="display display-sm uppercase leading-[0.95]" style={{ color: 'var(--text-1)', fontSize: 'clamp(28px, 3.2vw, 44px)' }}>{alert.rule_name}</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>{alert.description}</p>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className="text-xs font-mono px-2 py-0.5 rounded inline-flex items-center gap-1 num" style={{ background: 'rgba(225,29,72,0.1)', border: '1px solid rgba(225,29,72,0.2)', color: '#f87171' }}>
              <Crosshair size={10} /> {alert.mitre_technique}
            </span>
            <span className="text-xs" style={{ color: 'var(--text-4)' }}>→ {alert.mitre_tactic}</span>
          </div>
        </div>

        {/* AI confidence + verdict */}
        <div className="shrink-0 flex flex-col items-end gap-3">
          {probPct != null && <AiConfidenceCard alert={alert} probPct={probPct} />}

          {verdict ? (
            <div className="text-xs text-center px-3 py-2 rounded-xl font-bold"
              style={{ background: verdict.decision === 'TP' ? 'rgba(225,29,72,0.1)' : 'rgba(107,114,128,0.1)', border: `1px solid ${verdict.decision === 'TP' ? 'rgba(225,29,72,0.3)' : 'rgba(107,114,128,0.3)'}`, color: verdict.decision === 'TP' ? '#f87171' : '#9ca3af' }}>
              Verdict: {verdict.decision}
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              <button disabled={submitting} onClick={() => submitVerdictAction('TP')}
                className="btn-accent text-xs px-4 py-2 rounded-xl disabled:opacity-50">
                Confirm TP
              </button>
              <button disabled={submitting} onClick={() => submitVerdictAction('FP')}
                className="text-xs px-4 py-2 rounded-xl transition-all disabled:opacity-50 font-bold"
                style={{ background: 'rgba(107,114,128,0.1)', border: '1px solid rgba(107,114,128,0.25)', color: '#9ca3af' }}>
                Dismiss FP
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Attack Knowledge ── */}
      <AttackKnowledgeCard alert={alert} onPivot={goPivot} />

      {/* ── AI banner ── */}
      {alert.ai_explanation && (
        <div className="rounded-2xl px-5 py-4 text-sm leading-relaxed"
          style={{ background: 'rgba(225,29,72,0.06)', border: '1px solid rgba(225,29,72,0.2)' }}>
          <span className="font-bold text-red-400">AI Assessment: </span>
          <span style={{ color: '#fca5a5' }}>{alert.ai_explanation}</span>
        </div>
      )}

      {/* ── Tab nav (lucide icons, consistent) ── */}
      <div className="flex items-center gap-0.5 border-b overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
        {TABS.map(({ key, label, count, icon: I }) => {
          const active = activeTab === key
          return (
            <button key={key} onClick={() => setActiveTab(key)}
              className="relative flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium whitespace-nowrap transition-all border-b-2"
              style={{
                color: active ? '#f87171' : 'var(--text-3)',
                borderColor: active ? 'var(--accent)' : 'transparent',
                background: active ? 'rgba(225,29,72,.04)' : 'transparent',
              }}
            >
              <I size={13} />
              {label}
              {count != null && count > 0 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold num"
                  style={{ background: active ? 'rgba(225,29,72,0.15)' : 'var(--surface-3)', color: active ? 'var(--accent)' : 'var(--text-3)' }}>
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Tab content ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          {activeTab === 'agent' && (
            <Card title="Autonomous Investigation Agent">
              <AIAgentPanel sessionId={session.session_id} alertId={alertId} onPivot={goPivot} />
            </Card>
          )}
          {activeTab === 'timeline' && (
            <Card title={`Timeline · ${data.related_count} events`}><Timeline rows={timeline} /></Card>
          )}
          {activeTab === 'iocs' && (
            <Card title="Indicators of Compromise">
              <IOCs iocs={iocs} sessionId={session.session_id} onIntelLoaded={handleIntelLoaded} />
            </Card>
          )}
          {activeTab === 'intel' && (
            <Card title="Threat Intelligence" action={intelResults.length === 0 && <span className="text-xs" style={{ color: 'var(--text-4)' }}>Run lookups from IOCs tab</span>}>
              {intelResults.length > 0
                ? <div className="space-y-3">{intelResults.map(r => <IntelCard key={r.ip} ip={r.ip} data={r} />)}</div>
                : <div className="text-center py-8" style={{ color: 'var(--text-3)' }}>
                    <p>No threat intelligence results yet.</p>
                    <button onClick={() => setActiveTab('iocs')} className="text-xs mt-2 underline" style={{ color: 'var(--accent)' }}>Go to IOCs →</button>
                  </div>
              }
            </Card>
          )}
          {activeTab === 'playbook' && (
            <Card title={`Response Playbook · ${alert.rule_id}`}><PlaybookPanel ruleId={alert.rule_id} /></Card>
          )}
          {activeTab === 'entities' && (
            <Card title="Observed Entities"><Entities entities={entities} /></Card>
          )}
          {activeTab === 'shap' && (
            <Card title="SHAP Feature Attribution">
              {alert.shap_features?.length > 0 ? (
                <ShapChart shapFeatures={alert.shap_features} />
              ) : (
                <p className="text-sm text-gray-500 italic">No SHAP features available for this alert</p>
              )}
            </Card>
          )}
          {activeTab === 'behavior' && (
            <Card title="Behavioral Profile">
              <BehaviorProfile alert={alert} profiles={data?.behavioral_profiles || session?.behavioral_profiles} />
            </Card>
          )}
          {activeTab === 'graph' && (
            <Card title="Entity Relationship Graph">
              {data.graph ? (
                <GraphView nodes={data.graph.nodes} edges={data.graph.edges} />
              ) : (
                <p className="text-sm text-gray-500 italic">Loading graph...</p>
              )}
            </Card>
          )}
          {activeTab === 'chains' && (
            <Card title="Attack Chain Matching">
              <div className="mb-5 pb-5" style={{ borderBottom: '1px solid var(--border)' }}>
                <ChainNarrative sessionId={session.session_id} />
              </div>
              {session?.attackChains?.filter(c => c.matched_alerts?.includes(alertId)).length > 0 ? (
                <div className="space-y-2">
                  {session.attackChains.filter(c => c.matched_alerts?.includes(alertId)).map(chain => (
                    <ChainCard key={chain.chain_id} chain={chain} />
                  ))}
                </div>
              ) : (
                <p className="text-sm text-gray-500 italic">No attack chains detected for this alert</p>
              )}
            </Card>
          )}
        </div>

        {/* ── Sidebar ── */}
        <div className="space-y-4">
          {alert.asset_context && (
            <AssetCard asset={alert.asset_context} />
          )}

          <Card title="Alert Metadata">
            <div className="space-y-2 text-xs">
              {[
                ['Rule ID',      alert.rule_id,        true],
                ['Severity',     alert.severity,       false],
                alert.source_ip && ['Source IP', alert.source_ip, true],
                alert.dest_ip   && ['Dest IP',   alert.dest_ip,   true],
                alert.user      && ['User',      alert.user,      true],
                ['Events',       alert.event_count,    false],
                ['MITRE',        `${alert.mitre_technique} · ${alert.mitre_tactic}`, false],
                alert.timestamp && ['Timestamp', new Date(alert.timestamp).toUTCString(), false],
              ].filter(Boolean).map(([k, v, mono]) => (
                <div key={k} className="flex items-start justify-between gap-2">
                  <span style={{ color: 'var(--text-3)' }} className="shrink-0">{k}</span>
                  <div className="flex items-center gap-1.5">
                    <span className={`text-right ${mono ? 'font-mono text-white' : 'text-white'} truncate max-w-[140px]`}>{v}</span>
                    {mono && <CopyBtn text={String(v)} />}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Quick Navigation">
            <div className="grid grid-cols-2 gap-2">
              {TABS.map(({ key, label, count }) => (
                <button key={key} onClick={() => setActiveTab(key)}
                  className="text-xs px-3 py-2 rounded-lg text-left transition-all"
                  style={{
                    background: activeTab === key ? 'rgba(225,29,72,0.08)' : 'var(--surface-2)',
                    border: `1px solid ${activeTab === key ? 'rgba(225,29,72,0.25)' : 'var(--border)'}`,
                    color: activeTab === key ? 'var(--accent)' : 'var(--text-2)',
                  }}>
                  {label}{count != null && count > 0 && <span className="ml-1 opacity-50 text-[10px]">({count})</span>}
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
