import { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  Bot, Sparkles, Loader2, ShieldAlert, ShieldCheck, ListChecks,
  FileText, ClipboardList, Wand2, X as XIcon, ChevronRight,
  Search, Download, Filter as FilterIcon, Crosshair, Hash,
  Globe, AlertOctagon,
} from 'lucide-react'
import { submitVerdict, listVerdicts, getVerdictAssist, getPlaybook } from '../api/client'
import { useSession } from '../App'

// ── Constants ────────────────────────────────────────────────────────────────
const SEV_STYLE = {
  CRITICAL: { pill: 'text-red-500',    dot: 'bg-red-500',    pillBg: 'rgba(239,68,68,0.1)',   pillBorder: 'rgba(239,68,68,0.3)',   row: 'critical-row' },
  HIGH:     { pill: 'text-red-400',    dot: 'bg-red-400',    pillBg: 'rgba(244,63,94,0.1)',   pillBorder: 'rgba(244,63,94,0.3)',   row: '' },
  MEDIUM:   { pill: 'text-red-300',    dot: 'bg-red-300',    pillBg: 'rgba(225,29,72,0.1)',   pillBorder: 'rgba(225,29,72,0.3)',   row: '' },
  LOW:      { pill: 'text-zinc-400',   dot: 'bg-zinc-500',   pillBg: 'rgba(113,113,122,0.1)', pillBorder: 'rgba(113,113,122,0.3)', row: '' },
}
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

const aiRec = (alert) => {
  const s = alert.tp_probability != null ? alert.tp_probability
    : alert.ai_score != null ? alert.ai_score / 100 : null
  if (s == null) return null
  return s >= 0.6 ? 'TP' : 'FP'
}

// ── Severity badge (uses global .sev-chip token) ──────────────────────────────
const SEV_CLASS = {
  CRITICAL: 'sev-chip sev-chip-critical',
  HIGH:     'sev-chip sev-chip-high',
  MEDIUM:   'sev-chip sev-chip-medium',
  LOW:      'sev-chip sev-chip-low',
}
const SevBadge = ({ sev }) => (
  <span className={SEV_CLASS[sev] || SEV_CLASS.LOW}>{sev}</span>
)

// Build a human-readable list of signals that drove the AI score.
// Trustable scoring: shows WHICH features moved the model, not just a percent.
const scoreReasons = (alert) => {
  const reasons = []
  const sev = alert?.severity
  if (sev === 'CRITICAL') reasons.push(['+', 'Critical severity rule fired', '+25'])
  else if (sev === 'HIGH') reasons.push(['+', 'High severity classification', '+15'])
  const methods = alert?.detection_methods || []
  if (methods.includes('rule_based'))           reasons.push(['+', 'Deterministic rule match', '+10'])
  if (methods.includes('behavioral_anomaly'))   reasons.push(['+', 'UEBA baseline deviation', '+18'])
  if (methods.includes('pattern_correlation'))  reasons.push(['+', 'Cross-event correlation', '+12'])
  if (alert?.mitre_techniques?.length > 1)      reasons.push(['+', `${alert.mitre_techniques.length} MITRE techniques chained`, '+15'])
  else if (alert?.mitre_techniques?.[0] || alert?.mitre_technique)
    reasons.push(['+', `MITRE ${alert.mitre_techniques?.[0] || alert.mitre_technique} mapped`, '+5'])
  if (alert?.anomaly_score != null && alert.anomaly_score > 0.6) reasons.push(['+', `IsolationForest anomaly ${Math.round(alert.anomaly_score*100)}%`, '+10'])
  if (alert?.event_count > 5) reasons.push(['+', `${alert.event_count} correlated events`, '+8'])
  if (alert?.ai_rationale)    reasons.push(['•', alert.ai_rationale, ''])
  if (alert?.ai_explanation && !alert?.ai_rationale) reasons.push(['•', alert.ai_explanation, ''])
  if (!reasons.length) reasons.push(['•', 'Baseline rule confidence only', ''])
  return reasons
}

function ProbBar({ prob, alert }) {
  const [show, setShow] = useState(false)
  if (prob == null) return <span className="text-xs" style={{ color: 'var(--text-4)' }}>—</span>
  const pct  = Math.round(prob * 100)
  const col  = pct >= 75 ? '#ff0000' : pct >= 45 ? '#e11d48' : '#6b7280'
  const tier = pct >= 75 ? 'HIGH CONFIDENCE TP' : pct >= 45 ? 'LIKELY TP' : 'LOW CONFIDENCE'
  const reasons = alert ? scoreReasons(alert) : []
  return (
    <div
      className="relative flex items-center gap-2 min-w-[90px] cursor-help"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
      onClick={(e) => { e.stopPropagation(); setShow(s => !s) }}
    >
      <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: col, boxShadow: pct >= 75 ? '0 0 8px rgba(255,0,0,.5)' : 'none' }} />
      </div>
      <span className="text-xs tabular-nums font-mono inline-flex items-center gap-1" style={{ color: 'var(--text-2)' }}>
        {pct}%
        <span className="text-[9px]" style={{ color: 'var(--text-4)' }}>ⓘ</span>
      </span>
      {show && alert && (
        <div className="absolute z-50 left-0 top-full mt-2 w-72 rounded-xl p-3 shadow-2xl fade-in"
          style={{ background: 'var(--surface)', border: '1px solid rgba(225,29,72,.35)', boxShadow: '0 12px 32px rgba(0,0,0,.6), 0 0 0 1px rgba(225,29,72,.2)' }}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Why this score</span>
            <span className="text-[10px] font-bold num px-1.5 py-0.5 rounded" style={{ background: 'rgba(225,29,72,.12)', color: col, border: '1px solid rgba(225,29,72,.3)' }}>{tier}</span>
          </div>
          <p className="text-[10px] mb-2" style={{ color: 'var(--text-4)' }}>
            Composite of deterministic rules, UEBA, AI re-scoring. Hover any signal to trust the verdict.
          </p>
          <ul className="space-y-1 text-xs">
            {reasons.map(([k, txt, w], i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="font-mono shrink-0 mt-0.5" style={{ color: k === '+' ? '#f87171' : 'var(--text-4)' }}>{k}</span>
                <span className="flex-1" style={{ color: 'var(--text-2)' }}>{txt}</span>
                {w && <span className="font-mono text-[10px] num shrink-0" style={{ color: '#f87171' }}>{w}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

const VerdictBadge = ({ verdict }) => {
  if (!verdict) return <span className="text-xs italic" style={{ color: 'var(--text-4)' }}>pending</span>
  const isTP = verdict === 'TP'
  return (
    <span
      className="text-xs font-bold px-2 py-0.5 rounded-full"
      style={{
        background: isTP ? 'rgba(225,29,72,0.1)' : 'rgba(107,114,128,0.1)',
        border: `1px solid ${isTP ? 'rgba(225,29,72,0.3)' : 'rgba(107,114,128,0.3)'}`,
        color: isTP ? '#f87171' : '#9ca3af',
      }}
    >
      {verdict}
    </span>
  )
}

function alertAge(ts) {
  if (!ts) return null
  const m = Math.floor((Date.now() - new Date(ts)) / 60000)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

const getMitreTip = (technique) => {
  if (!technique) return '';
  if (technique.includes('T1110')) return 'T1110: Brute Force - Adversaries may use brute force techniques to attempt access to accounts.';
  if (technique.includes('T1550')) return 'T1550: Use Alternate Authentication Material - Adversaries may use stolen credentials like pass-the-hash to bypass normal auth.';
  return `${technique}: Click to search MITRE ATT&CK database.`;
}

const MethodBadges = ({ methods = [] }) => {
  const methodMap = {
    rule_based: { label: 'R', color: '#3b82f6', bg: 'rgba(59,130,246,0.15)' },
    behavioral_anomaly: { label: 'A', color: '#a855f7', bg: 'rgba(168,85,247,0.15)' },
    pattern_correlation: { label: 'C', color: '#ec4899', bg: 'rgba(236,72,153,0.15)' },
  }
  return (
    <div className="flex gap-1">
      {methods.map(m => {
        const cfg = methodMap[m]
        return cfg ? (
          <span key={m} className="text-[10px] font-bold px-1.5 py-0.5 rounded"
            style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}33` }}
            title={m}>
            {cfg.label}
          </span>
        ) : null
      })}
    </div>
  )
}

// ── Alert Row ─────────────────────────────────────────────────────────────────
function AlertRow({ alert, verdicts, onVerdict, selected, onSelect, focused, onOpenDrawer }) {
  const [submitting, setSub]  = useState(false)
  const verdict   = verdicts[alert.alert_id]
  const rowRef    = useRef()
  const s         = SEV_STYLE[alert.severity] || SEV_STYLE.LOW

  useEffect(() => {
    if (focused && rowRef.current) rowRef.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [focused])

  const submit = async (decision) => {
    if (submitting) return
    setSub(true)
    try {
      await onVerdict({ alert_id: alert.alert_id, decision })
    } finally { setSub(false) }
  }

  return (
    <tr
      ref={rowRef}
      onClick={() => onOpenDrawer(alert)}
      data-focused={focused ? 'true' : 'false'}
      className={`border-b cursor-pointer data-row ${s.row}`}
      style={{
        borderColor: 'var(--border)',
        background: selected ? 'rgba(225,29,72,0.04)' : 'transparent',
      }}
    >
      <td className="px-3 py-3 w-8" onClick={e => e.stopPropagation()}>
        <input type="checkbox" checked={selected} onChange={() => onSelect(alert.alert_id)} />
      </td>
      <td className="px-3 py-3"><SevBadge sev={alert.severity} /></td>
      <td className="px-3 py-3">
        <p className="text-sm font-semibold text-white leading-tight">{alert.rule_name}</p>
        <p className="text-xs font-mono mt-0.5" style={{ color: 'var(--text-4)' }}>{alert.rule_id}</p>
      </td>
      <td className="px-3 py-3 hidden md:table-cell max-w-xs">
        <p className="text-xs truncate" style={{ color: 'var(--text-2)' }}>{alert.description}</p>
      </td>
      <td className="px-3 py-3 hidden lg:table-cell">
        {alert.source_ip
          ? <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'var(--surface-3)', color: 'var(--text-1)' }}>{alert.source_ip}</span>
          : <span style={{ color: 'var(--text-4)' }}>—</span>}
      </td>
      <td className="px-3 py-3 hidden xl:table-cell" onClick={e => e.stopPropagation()}>
        <span className="text-xs font-mono px-1.5 py-0.5 rounded interactive-tag transition-transform hover:scale-105 inline-block cursor-help"
          data-tip={getMitreTip(alert.mitre_techniques?.[0] || alert.mitre_technique)}
          style={{ background: 'rgba(225,29,72,0.1)', border: '1px solid rgba(225,29,72,0.2)', color: '#f87171' }}>
          {alert.mitre_techniques?.[0] || alert.mitre_technique || '—'}
        </span>
      </td>
      <td className="px-3 py-3 hidden sm:table-cell">
        <MethodBadges methods={alert.detection_methods || []} />
      </td>
      <td className="px-3 py-3" onClick={e => e.stopPropagation()}>
        <ProbBar prob={alert.tp_probability || (alert.ai_score ? alert.ai_score / 100 : null)} alert={alert} />
      </td>
      <td className="px-3 py-3 hidden sm:table-cell">
        {alertAge(alert.timestamp) && <span className="text-xs" style={{ color: 'var(--text-4)' }}>{alertAge(alert.timestamp)}</span>}
      </td>
      <td className="px-3 py-3" onClick={e => e.stopPropagation()}>
        {verdict ? <VerdictBadge verdict={verdict.decision} /> : (
          <div className="flex items-center gap-1">
            {aiRec(alert) && (
              <span className="text-[9px] font-bold px-1 py-0.5 rounded mr-0.5" title="AI recommendation"
                style={{ background: 'rgba(225,29,72,0.08)', color: aiRec(alert) === 'TP' ? '#f87171' : '#9ca3af', border: '1px solid var(--border-2)' }}>
                AI:{aiRec(alert)}
              </span>
            )}
            <button disabled={submitting} onClick={() => submit('TP')}
              className="text-xs px-2 py-1 rounded transition-all disabled:opacity-40 hover-glow"
              style={{ background: 'rgba(225,29,72,0.15)', border: '1px solid rgba(225,29,72,0.3)', color: '#f87171' }}
              onMouseEnter={e => { e.target.style.background = 'rgba(225,29,72,0.25)' }}
              onMouseLeave={e => { e.target.style.background = 'rgba(225,29,72,0.15)' }}
            >TP</button>
            <button disabled={submitting} onClick={() => submit('FP')}
              className="text-xs px-2 py-1 rounded transition-all disabled:opacity-40"
              style={{ background: 'rgba(107,114,128,0.15)', border: '1px solid rgba(107,114,128,0.3)', color: '#9ca3af' }}
              onMouseEnter={e => { e.target.style.background = 'rgba(107,114,128,0.25)' }}
              onMouseLeave={e => { e.target.style.background = 'rgba(107,114,128,0.15)' }}
            >FP</button>
          </div>
        )}
      </td>
      <td className="px-3 py-3 text-xs text-right" style={{ color: 'var(--text-4)' }}>
        <ChevronRight size={14} className="inline-block" />
      </td>
    </tr>
  )
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
const STATIC_TP_REASONS = [
  'Confirmed malicious activity', 'Matches known attack pattern',
  'Corroborated by threat intel', 'Part of a correlated attack chain',
]
const STATIC_FP_REASONS = [
  'Whitelisted IP', 'Scheduled / automated task', 'Known security scanner',
  'Test / lab traffic', 'Benign baseline noise',
]

function SectionLabel({ icon: Icon, children }) {
  return (
    <p className="text-xs font-bold uppercase tracking-widest flex items-center gap-2" style={{ color: 'var(--text-3)' }}>
      {Icon && <Icon size={13} style={{ color: 'var(--accent)' }} />}{children}
    </p>
  )
}

function CheckList({ items, checked, onToggle, render }) {
  return (
    <div className="rounded-xl p-4 space-y-2" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
      {items.map((it, i) => (
        <label key={i} className="flex items-start gap-3 cursor-pointer group">
          <input type="checkbox" className="mt-0.5" checked={checked.has(i)} onChange={() => onToggle(i)} />
          <span className="text-sm group-hover:text-white transition-colors"
            style={{ color: checked.has(i) ? 'var(--text-4)' : 'var(--text-2)', textDecoration: checked.has(i) ? 'line-through' : 'none' }}>
            {render(it)}
          </span>
        </label>
      ))}
    </div>
  )
}

function DetailDrawer({ alert, onClose, verdict, submitVerdict, sessionId }) {
  const [submitting, setSub] = useState(false)
  const [decision, setDecision] = useState(null)        // 'TP' | 'FP'
  const [reason, setReason] = useState('')
  const [otherText, setOtherText] = useState('')
  const [notes, setNotes] = useState('')
  const [assist, setAssist] = useState(null)
  const [loadingAssist, setLoadingAssist] = useState(true)
  const [playbook, setPlaybook] = useState(null)
  const [aiDone, setAiDone] = useState(new Set())
  const [manDone, setManDone] = useState(new Set())
  const navigate = useNavigate()

  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  useEffect(() => {
    let alive = true
    setLoadingAssist(true)
    setAssist(null)
    if (sessionId) {
      getVerdictAssist(sessionId, alert.alert_id)
        .then(({ data }) => { if (alive) setAssist(data.assist) })
        .catch(() => {})
        .finally(() => alive && setLoadingAssist(false))
      getPlaybook(alert.rule_id).then(({ data }) => alive && setPlaybook(data)).catch(() => {})
    } else {
      setLoadingAssist(false)
    }
    return () => { alive = false }
  }, [alert.alert_id, sessionId])

  const tpReasons = (assist?.tp_reasons?.length ? assist.tp_reasons : STATIC_TP_REASONS)
  const fpReasons = (assist?.fp_reasons?.length ? assist.fp_reasons : STATIC_FP_REASONS)
  const reasonOpts = decision === 'TP' ? tpReasons : decision === 'FP' ? fpReasons : []

  const pickDecision = (d) => {
    setDecision(d)
    setReason('')
    setOtherText('')
  }

  const submit = async () => {
    if (!decision) { toast.error('Choose True Positive or False Positive'); return }
    const isOther = reason === '__other__' || !reason
    const finalReason = isOther ? 'other' : reason
    if (isOther && !otherText.trim()) { toast.error('Enter a reason'); return }
    setSub(true)
    await submitVerdict({
      alert_id: alert.alert_id,
      decision,
      reason: finalReason,
      reason_detail: isOther ? otherText.trim() : undefined,
      fp_reason: decision === 'FP' ? (isOther ? 'other' : 'analyst_specified') : undefined,
      notes: notes.trim() || undefined,
      ai_notes: assist?.ai_notes || undefined,
    })
    setSub(false)
    onClose()
  }

  const score = alert.tp_probability != null ? alert.tp_probability
    : alert.ai_score != null ? alert.ai_score / 100 : null

  return (
    <>
      <div className="drawer-overlay fade-in" onClick={onClose} />
      <div className="drawer-content slide-up" style={{ width: '100%', maxWidth: '680px' }}>
        <div className="p-6 border-b flex items-center justify-between" style={{ borderColor: 'var(--border)' }}>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-3">
              {alert.rule_name}
              <SevBadge sev={alert.severity} />
            </h2>
            <p className="text-sm font-mono mt-1" style={{ color: 'var(--text-3)' }}>{alert.rule_id} · {alert.alert_id}</p>
          </div>
          <button onClick={onClose} className="transition-colors hover:text-white" style={{ color: 'var(--text-3)' }}><XIcon size={22} /></button>
        </div>

        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          {/* Expanded description */}
          <div className="space-y-2">
            <SectionLabel icon={FileText}>Incident Detail</SectionLabel>
            <p className="text-sm leading-relaxed" style={{ color: 'var(--text-1)' }}>
              {assist?.expanded_description || alert.description}
            </p>
            {loadingAssist && (
              <p className="text-xs flex items-center gap-1.5" style={{ color: 'var(--text-4)' }}>
                <Loader2 size={12} className="animate-spin" /> AI expanding analysis…
              </p>
            )}
          </div>

          {/* AI reasoning (model score) */}
          {(alert.ai_rationale || alert.ai_explanation) && (
            <div className="rounded-xl p-4 text-sm leading-relaxed" style={{ background: 'rgba(225,29,72,0.06)', border: '1px solid rgba(225,29,72,0.2)' }}>
              <div className="flex items-center gap-2 mb-2">
                <Sparkles size={15} className="text-red-400" />
                <span className="font-bold text-red-400">AI Detection Reasoning</span>
                {score != null && (
                  <span className="ml-auto font-mono text-xs" style={{ color: 'rgba(248,113,113,0.8)' }}>TP {Math.round(score * 100)}%</span>
                )}
              </div>
              <span style={{ color: '#fca5a5' }}>{alert.ai_rationale || alert.ai_explanation}</span>
            </div>
          )}

          {/* Rule reasoning + evidence — surfaced from backend rule catalog so
              every alert answers "why is this flagged?" without an LLM call. */}
          {(alert.extra?.reasoning || alert.extra?.validates || alert.extra?.evidence?.length > 0) && (
            <div className="space-y-2">
              <SectionLabel icon={ShieldAlert}>Rule Reasoning &amp; Evidence</SectionLabel>
              <div className="rounded-xl p-4 space-y-3 text-sm" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                {alert.extra?.reasoning && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>Why this is malicious</div>
                    <p>{alert.extra.reasoning}</p>
                  </div>
                )}
                {alert.extra?.validates && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>What the rule validated</div>
                    <p style={{ color: 'var(--text-1)' }}>{alert.extra.validates}</p>
                  </div>
                )}
                {Array.isArray(alert.extra?.confidence_signals) && alert.extra.confidence_signals.length > 0 && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>Corroborating signals</div>
                    <div className="flex flex-wrap gap-1.5">
                      {alert.extra.confidence_signals.map((s, i) => (
                        <span key={i} className="text-[11px] px-2 py-0.5 rounded-full" style={{ background: 'rgba(225,29,72,0.12)', color: '#fca5a5', border: '1px solid rgba(225,29,72,0.25)' }}>{s}</span>
                      ))}
                    </div>
                  </div>
                )}
                {Array.isArray(alert.extra?.evidence) && alert.extra.evidence.length > 0 && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>Sampled log facts ({alert.extra.evidence.length})</div>
                    <div className="space-y-2">
                      {alert.extra.evidence.map((ev, i) => (
                        <div key={i} className="rounded-lg p-2 text-[11px] font-mono" style={{ background: 'var(--bg)', border: '1px solid var(--border-2)' }}>
                          {Object.entries(ev).filter(([k]) => k !== '_log_index').map(([k, v]) => (
                            <div key={k} className="flex gap-2 leading-relaxed">
                              <span style={{ color: 'var(--text-4)' }}>{k}:</span>
                              <span style={{ color: 'var(--text-1)' }} className="break-all">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {alert.extra?.recommended_action && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>Recommended action</div>
                    <p style={{ color: '#86efac' }}>{alert.extra.recommended_action}</p>
                  </div>
                )}
                {alert.extra?.false_positive_notes && (
                  <div>
                    <div className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: 'var(--text-4)' }}>When this would be benign</div>
                    <p style={{ color: 'var(--text-3)' }}>{alert.extra.false_positive_notes}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* AI case notes */}
          {assist?.ai_notes && (
            <div className="space-y-2">
              <SectionLabel icon={Bot}>AI Case Notes {assist.ai_generated === false && <span className="normal-case font-normal" style={{ color: 'var(--text-4)' }}>(heuristic)</span>}</SectionLabel>
              <div className="rounded-xl p-4 text-sm leading-relaxed" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                {assist.ai_notes}
              </div>
            </div>
          )}

          {alert.raw_log && (
            <div className="space-y-2">
              <SectionLabel icon={FileText}>Raw Evidence</SectionLabel>
              <pre className="p-4 rounded-xl text-xs font-mono overflow-x-auto" style={{ background: 'var(--bg)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                {String(alert.raw_log).split('\\n').map((line, i) => (
                  <div key={i} className="py-0.5 hover:bg-white/[0.05]">{line}</div>
                ))}
              </pre>
            </div>
          )}

          {/* AI suggested response */}
          <div className="space-y-2">
            <SectionLabel icon={Wand2}>AI-Suggested Response</SectionLabel>
            {assist?.ai_playbook?.length ? (
              <CheckList
                items={assist.ai_playbook}
                checked={aiDone}
                onToggle={(i) => setAiDone(s => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n })}
                render={(it) => (
                  <><span className="text-[10px] font-bold px-1.5 py-0.5 rounded mr-2" style={{ background: 'rgba(225,29,72,0.12)', color: '#f87171' }}>{it.phase}</span>{it.action}</>
                )}
              />
            ) : (
              <p className="text-xs" style={{ color: 'var(--text-4)' }}>{loadingAssist ? 'Generating tailored response…' : 'No AI response available.'}</p>
            )}
          </div>

          {/* Manual playbook — further steps */}
          {playbook?.steps?.length > 0 && (
            <div className="space-y-2">
              <SectionLabel icon={ClipboardList}>Manual Playbook · {playbook.title}</SectionLabel>
              <CheckList
                items={playbook.steps}
                checked={manDone}
                onToggle={(i) => setManDone(s => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n })}
                render={(st) => (
                  <><span className="text-[10px] font-bold px-1.5 py-0.5 rounded mr-2" style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}>{st.phase}</span>{st.action}</>
                )}
              />
            </div>
          )}

          {/* Analyst verdict */}
          <div className="space-y-3 pt-4 border-t" style={{ borderColor: 'var(--border)' }}>
            <SectionLabel icon={ListChecks}>Analyst Verdict</SectionLabel>
            {verdict ? (
              <div className="rounded-xl p-4 space-y-1.5" style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)' }}>
                <div className="flex items-center gap-2">
                  <VerdictBadge verdict={verdict.decision} />
                  <span className="text-sm text-white">verdict recorded</span>
                </div>
                {(verdict.reason || verdict.fp_reason) && <p className="text-xs" style={{ color: 'var(--text-3)' }}>Reason: {String(verdict.reason || verdict.fp_reason).replace(/_/g, ' ')}{verdict.reason_detail ? ` — ${verdict.reason_detail}` : ''}</p>}
                {verdict.notes && <p className="text-xs italic" style={{ color: 'var(--text-3)' }}>Analyst: "{verdict.notes}"</p>}
                {verdict.ai_notes && <p className="text-xs italic" style={{ color: 'var(--text-4)' }}>AI: "{verdict.ai_notes}"</p>}
              </div>
            ) : (
              <div className="space-y-4">
                {assist?.recommended_verdict && (
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                    AI recommends <span className="font-bold" style={{ color: assist.recommended_verdict === 'TP' ? '#f87171' : '#9ca3af' }}>{assist.recommended_verdict}</span>
                  </p>
                )}
                <div className="grid grid-cols-2 gap-3">
                  <button onClick={() => pickDecision('TP')}
                    className="text-sm font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2"
                    style={{
                      background: decision === 'TP' ? 'linear-gradient(135deg,#9f1239,#e11d48)' : 'rgba(225,29,72,0.1)',
                      border: '1px solid rgba(225,29,72,0.3)', color: decision === 'TP' ? '#fff' : '#f87171',
                    }}>
                    <ShieldAlert size={16} /> True Positive
                  </button>
                  <button onClick={() => pickDecision('FP')}
                    className="text-sm font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2"
                    style={{
                      background: decision === 'FP' ? 'rgba(107,114,128,0.3)' : 'rgba(107,114,128,0.1)',
                      border: '1px solid rgba(107,114,128,0.3)', color: '#9ca3af',
                    }}>
                    <ShieldCheck size={16} /> False Positive
                  </button>
                </div>

                {decision && (
                  <>
                    <div>
                      <label className="text-xs block mb-1.5" style={{ color: 'var(--text-3)' }}>
                        Why {decision === 'TP' ? 'True' : 'False'} Positive? {assist?.ai_generated && <span style={{ color: 'var(--text-4)' }}>(AI-suggested, alert-specific)</span>}
                      </label>
                      <select value={reason} onChange={e => setReason(e.target.value)}
                        className="w-full text-sm rounded-xl px-3 py-2.5 focus:outline-none"
                        style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }}>
                        <option value="">— Select a reason —</option>
                        {reasonOpts.map((r, i) => <option key={i} value={r}>{r}</option>)}
                        <option value="__other__">Other (specify)…</option>
                      </select>
                    </div>
                    {(reason === '__other__') && (
                      <input value={otherText} onChange={e => setOtherText(e.target.value)}
                        placeholder="Describe the reason…"
                        className="w-full text-sm rounded-xl px-3 py-2.5 focus:outline-none"
                        style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }} />
                    )}
                    <div>
                      <label className="text-xs block mb-1.5" style={{ color: 'var(--text-3)' }}>Manual analyst notes <span style={{ color: 'var(--text-4)' }}>(optional)</span></label>
                      <textarea rows={3} value={notes} onChange={e => setNotes(e.target.value)}
                        placeholder="Your own evidence, reasoning, context…"
                        className="w-full text-sm rounded-xl px-3 py-2.5 focus:outline-none resize-none"
                        style={{ background: 'var(--surface-3)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }} />
                      <p className="text-[10px] mt-1" style={{ color: 'var(--text-4)' }}>AI case notes are recorded automatically alongside yours.</p>
                    </div>
                    <button disabled={submitting} onClick={submit}
                      className="w-full text-sm font-bold py-3 rounded-xl transition-all disabled:opacity-50 hover-glow"
                      style={{ background: 'linear-gradient(135deg,#9f1239,#e11d48)', color: 'white' }}>
                      {submitting ? 'Recording…' : `Record ${decision} Verdict`}
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )
}

// ── Sort header ───────────────────────────────────────────────────────────────
function SortTh({ label, sortKey, current, onClick, className = '' }) {
  const active = current.key === sortKey
  return (
    <th onClick={() => onClick(sortKey)}
      className={`px-3 py-3 cursor-pointer select-none transition-colors text-left ${className}`}
      style={{ color: active ? 'var(--accent)' : 'var(--text-3)' }}
    >
      <span className="flex items-center gap-1">
        {label}
        {active && <span style={{ color: 'var(--accent)', fontSize: '10px' }}>{current.dir === 'desc' ? '▼' : '▲'}</span>}
      </span>
    </th>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function Triage() {
  const { session, setSession } = useSession()
  const [verdicts,   setVerdicts]   = useState(session?.verdicts ?? {})
  const [sortCfg,    setSortCfg]    = useState({ key: 'severity', dir: 'desc' })
  const [filterSev,  setFilterSev]  = useState('ALL')
  const [filterVerd, setFilterVerd] = useState('ALL')
  const [search,     setSearch]     = useState('')
  const [selected,   setSelected]   = useState(new Set())
  const [focusIdx,   setFocusIdx]   = useState(-1)
  const [drawerAlert, setDrawerAlert] = useState(null)
  const searchRef = useRef()

  useEffect(() => {
    if (session?.verdicts) {
      setVerdicts(session.verdicts)
    }
    if (session?.session_id && !session.session_id.startsWith('demo-')) {
      listVerdicts(session.session_id).then(({ data }) => {
        const verdictMap = data.reduce((acc, v) => {
          acc[v.alert_id] = v
          return acc
        }, {})
        setVerdicts(verdictMap)
        setSession(s => ({ ...s, verdicts: verdictMap }))
      }).catch(err => console.error('Failed to load verdicts:', err))
    }
  }, [session?.session_id])

  const alerts = session?.alerts ?? []

  const displayed = useMemo(() => {
    let list = [...alerts]
    if (filterSev  !== 'ALL') list = list.filter(a => a.severity === filterSev)
    if (filterVerd === 'pending') list = list.filter(a => !verdicts[a.alert_id])
    if (filterVerd === 'TP') list = list.filter(a => verdicts[a.alert_id]?.decision === 'TP')
    if (filterVerd === 'FP') list = list.filter(a => verdicts[a.alert_id]?.decision === 'FP')
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(a =>
        a.rule_name.toLowerCase().includes(q) ||
        a.rule_id.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q) ||
        a.source_ip?.toLowerCase().includes(q) ||
        (a.mitre_techniques && a.mitre_techniques[0]?.toLowerCase().includes(q))
      )
    }
    list.sort((a, b) => {
      let cmp = 0
      if (sortCfg.key === 'severity')    cmp = SEV_RANK[b.severity] - SEV_RANK[a.severity]
      if (sortCfg.key === 'probability') cmp = (b.tp_probability ?? (b.ai_score ? b.ai_score/100 : 0)) - (a.tp_probability ?? (a.ai_score ? a.ai_score/100 : 0))
      if (sortCfg.key === 'rule')        cmp = a.rule_id.localeCompare(b.rule_id)
      if (sortCfg.key === 'age')         cmp = new Date(b.timestamp ?? 0) - new Date(a.timestamp ?? 0)
      return sortCfg.dir === 'desc' ? cmp : -cmp
    })
    return list
  }, [alerts, sortCfg, filterSev, filterVerd, search, verdicts])

  const pendingCount = alerts.filter(a => !verdicts[a.alert_id]).length
  const tpCount      = Object.values(verdicts).filter(v => v.decision === 'TP').length
  const fpCount      = Object.values(verdicts).filter(v => v.decision === 'FP').length
  const coverage     = alerts.length > 0 ? Math.round(((tpCount + fpCount) / alerts.length) * 100) : 0
  const allSelected  = displayed.length > 0 && displayed.every(a => selected.has(a.alert_id))

  const toggleSort   = (key) => setSortCfg(c => c.key === key ? { key, dir: c.dir === 'desc' ? 'asc' : 'desc' } : { key, dir: 'desc' })
  const toggleSelect = useCallback((id) => setSelected(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n }), [])
  const toggleAll    = () => setSelected(allSelected ? new Set() : new Set(displayed.map(a => a.alert_id)))

  const handleVerdict = async (payload) => {
    // In a real app we'd await an API call, here we'll just mock or safely catch
    try {
      if (session.session_id && !session.session_id.startsWith('demo-')) {
        await submitVerdict({ ...payload, session_id: session.session_id })
      }
    } catch {}
    const updated = { ...verdicts, [payload.alert_id]: payload }
    setVerdicts(updated)
    setSession(s => ({ ...s, verdicts: updated }))
    toast.success(payload.decision === 'TP' ? '🔴 True Positive confirmed' : '✅ False Positive dismissed')
  }

  const bulkVerdict = async (decision) => {
    const ids = [...selected].filter(id => !verdicts[id])
    if (!ids.length) { toast.error('All selected alerts already have verdicts'); return }
    let upd = { ...verdicts }
    for (const id of ids) {
      try {
        if (session.session_id && !session.session_id.startsWith('demo-')) {
           await submitVerdict({ alert_id: id, decision, session_id: session.session_id })
        }
        upd = { ...upd, [id]: { alert_id: id, decision } }
      } catch {}
    }
    setVerdicts(upd)
    setSession(s => ({ ...s, verdicts: upd }))
    setSelected(new Set())
    toast.success(`${ids.length} alerts marked as ${decision}`)
  }

  const applyAiSuggestions = async (scope) => {
    const pool = scope === 'selected' ? [...selected] : displayed.map(a => a.alert_id)
    const targets = alerts.filter(a => pool.includes(a.alert_id) && !verdicts[a.alert_id] && aiRec(a))
    if (!targets.length) { toast.error('No pending alerts with an AI recommendation'); return }
    let upd = { ...verdicts }
    for (const a of targets) {
      const decision = aiRec(a)
      const payload = {
        alert_id: a.alert_id, decision, reason: 'ai_recommended',
        fp_reason: decision === 'FP' ? 'ai_recommended' : undefined,
        notes: 'Auto-applied from AI recommendation',
      }
      try {
        if (session.session_id && !session.session_id.startsWith('demo-')) {
          await submitVerdict({ ...payload, session_id: session.session_id })
        }
      } catch {}
      upd = { ...upd, [a.alert_id]: payload }
    }
    setVerdicts(upd)
    setSession(s => ({ ...s, verdicts: upd }))
    setSelected(new Set())
    toast.success(`AI applied to ${targets.length} alert(s)`)
  }

  const exportCSV = () => {
    const hdr  = ['rule_id','rule_name','severity','source_ip','mitre_technique','mitre_tactic','tp_probability','verdict']
    const rows = displayed.map(a => [a.rule_id, `"${a.rule_name}"`, a.severity, a.source_ip??'', a.mitre_techniques?.[0]??'', a.mitre_tactics?.[0]??'', a.tp_probability!=null?Math.round(a.tp_probability*100)+'%':'', verdicts[a.alert_id]?.decision??'pending'])
    const url  = URL.createObjectURL(new Blob([[hdr,...rows].map(r=>r.join(',')).join('\n')], { type:'text/csv' }))
    Object.assign(document.createElement('a'), { href: url, download: 'triage_export.csv' }).click()
    URL.revokeObjectURL(url)
    toast.success('Exported as CSV')
  }

  useEffect(() => {
    const handler = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return
      if (e.key === '/') { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'j' || e.key === 'J') setFocusIdx(i => Math.min(i+1, displayed.length-1))
      if (e.key === 'k' || e.key === 'K') setFocusIdx(i => Math.max(i-1, 0))
      if (e.key === 'Enter' && focusIdx >= 0) setDrawerAlert(displayed[focusIdx])
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [displayed, focusIdx])

  const inputStyle = {
    background: 'var(--surface)',
    border: '1px solid var(--border-2)',
    color: 'var(--text-1)',
    borderRadius: '10px',
    outline: 'none',
    transition: 'border-color 0.15s',
  }

  return (
    <div className="space-y-4 fade-in pb-24">

      {/* ── Header ── */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center icon-3d-red">
              <ShieldAlert size={20} color="#f43f5e" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold text-white leading-tight">Alert Triage Queue</h1>
              <p className="text-sm num" style={{ color: 'var(--text-3)' }}>
                {alerts.length} total · <span className="text-red-400">{tpCount} TP</span> · <span style={{ color: 'var(--text-2)' }}>{fpCount} FP</span> · <span className="text-amber-400">{pendingCount} pending</span>
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => applyAiSuggestions('all')} disabled={pendingCount === 0}
            className="text-xs px-3 py-1.5 rounded-lg transition-all disabled:opacity-40 inline-flex items-center gap-1.5 font-semibold hover-glow"
            style={{ border: '1px solid rgba(225,29,72,0.3)', color: '#f87171', background: 'rgba(225,29,72,0.08)' }}>
            <Wand2 size={13} /> Apply AI to pending
          </button>
          <button onClick={exportCSV} disabled={displayed.length === 0}
            className="text-xs px-3 py-1.5 rounded-lg transition-all disabled:opacity-40 inline-flex items-center gap-1.5"
            style={{ border: '1px solid var(--border-2)', color: 'var(--text-2)', background: 'var(--surface)' }}>
            <Download size={12} /> Export CSV
          </button>
        </div>
      </div>

      {/* ── Progress Indicator (Premium) ── */}
      {alerts.length > 0 && (
        <div className="p-4 rounded-2xl mb-4 flex items-center gap-6 section-zoom" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
          <div className="flex-1">
            <div className="flex justify-between text-xs mb-2">
              <span className="font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Triage Coverage</span>
              <span className={coverage === 100 ? 'text-red-400 font-bold' : 'text-red-600 font-bold'}>{coverage}%</span>
            </div>
            <div className="h-3 rounded-full flex overflow-hidden" style={{ background: 'var(--surface-3)', boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.5)' }}>
              <div className="h-full transition-all duration-1000 ease-out relative overflow-hidden" style={{ width: `${coverage}%`, background: 'linear-gradient(90deg, #9f1239, #e11d48, #f43f5e)' }}>
                 <div className="absolute inset-0 progress-animated" style={{ opacity: 0.3 }}></div>
              </div>
            </div>
          </div>
          <div className="hidden sm:block border-l pl-6" style={{ borderColor: 'var(--border-2)' }}>
             <p className="text-[10px] font-bold uppercase tracking-widest mb-0.5" style={{ color: 'var(--text-4)' }}>Resolved</p>
             <p className="text-xl font-mono text-white">{alerts.length - pendingCount} <span className="text-sm" style={{ color: 'var(--text-3)' }}>/ {alerts.length}</span></p>
          </div>
        </div>
      )}

      {/* ── Filters ── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-4)' }} />
          <input
            ref={searchRef}
            value={search}
            onChange={e => { setSearch(e.target.value); setFocusIdx(-1) }}
            placeholder="Search rules, IPs, techniques… (/)"
            className="w-full text-sm pl-9 pr-8 py-2"
            style={{ ...inputStyle, paddingLeft: '2.25rem' }}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xl leading-none transition-colors" style={{ color: 'var(--text-4)' }}>×</button>
          )}
        </div>

        {[
          { val: filterSev,  set: setFilterSev,  opts: [['ALL','All Severities'],['CRITICAL','Critical'],['HIGH','High'],['MEDIUM','Medium'],['LOW','Low']] },
          { val: filterVerd, set: setFilterVerd, opts: [['ALL','All Verdicts'],['pending','Pending'],['TP','True Positive'],['FP','False Positive']] },
        ].map(({ val, set, opts }, i) => (
          <select key={i} value={val} onChange={e => set(e.target.value)}
            className="text-sm px-3 py-2"
            style={{ ...inputStyle, minWidth: '130px' }}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
          >
            {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        ))}

        {(search || filterSev !== 'ALL' || filterVerd !== 'ALL') && (
          <span className="text-xs" style={{ color: 'var(--text-3)' }}>{displayed.length} result{displayed.length !== 1 ? 's' : ''}</span>
        )}
      </div>

      {/* ── Table ── */}
      {alerts.length === 0 ? (
        <div className="text-center py-24 section-zoom">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 icon-3d-red">
            <ShieldCheck size={32} color="#4ade80" strokeWidth={1.5} />
          </div>
          <p className="font-semibold text-white">No alerts detected</p>
          <p className="text-sm mt-1" style={{ color: 'var(--text-3)' }}>The uploaded log file appears clean.</p>
        </div>
      ) : displayed.length === 0 ? (
        <div className="text-center py-16" style={{ color: 'var(--text-3)' }}>
          <FilterIcon size={28} className="mx-auto mb-3" style={{ color: 'var(--text-4)' }} />
          <p>No alerts match your filters.</p>
          <button onClick={() => { setSearch(''); setFilterSev('ALL'); setFilterVerd('ALL') }} className="text-xs mt-2 underline" style={{ color: 'var(--accent)' }}>
            Clear all filters
          </button>
        </div>
      ) : (
        <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
          <table className="w-full text-left">
            <thead className="border-b" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
              <tr className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>
                <th className="px-3 py-3 w-8"><input type="checkbox" checked={allSelected} onChange={toggleAll} /></th>
                <SortTh label="Severity"    sortKey="severity"    current={sortCfg} onClick={toggleSort} />
                <SortTh label="Rule"        sortKey="rule"        current={sortCfg} onClick={toggleSort} />
                <th className="px-3 py-3 hidden md:table-cell">Description</th>
                <th className="px-3 py-3 hidden lg:table-cell">Source IP</th>
                <th className="px-3 py-3 hidden xl:table-cell">MITRE</th>
                <th className="px-3 py-3 hidden sm:table-cell">Methods</th>
                <SortTh label="AI Prob"     sortKey="probability" current={sortCfg} onClick={toggleSort} />
                <SortTh label="Age"         sortKey="age"         current={sortCfg} onClick={toggleSort} className="hidden sm:table-cell" />
                <th className="px-3 py-3">Verdict</th>
                <th className="px-3 py-3 w-8" />
              </tr>
            </thead>
            <tbody>
              {displayed.map((alert, idx) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  verdicts={verdicts}
                  onVerdict={handleVerdict}
                  selected={selected.has(alert.alert_id)}
                  onSelect={toggleSelect}
                  focused={focusIdx === idx}
                  onOpenDrawer={setDrawerAlert}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Floating Bulk Action Bar ── */}
      {selected.size > 0 && (
        <div className="action-bar slide-up">
          <span className="text-xs font-bold px-2" style={{ color: 'var(--text-1)' }}>{selected.size} alerts selected</span>
          <div className="w-px h-4" style={{ background: 'var(--border-2)' }} />
          <button onClick={() => bulkVerdict('TP')} className="text-xs px-4 py-2 rounded-full btn-accent flex items-center gap-1.5 font-bold hover-glow">
            <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" /> Mark TP
          </button>
          <button onClick={() => bulkVerdict('FP')} className="text-xs px-4 py-2 rounded-full font-bold transition-all hover:bg-neutral-800/50"
            style={{ background: 'rgba(107,114,128,0.1)', border: '1px solid rgba(107,114,128,0.2)', color: '#9ca3af' }}>
            Mark FP
          </button>
          <button onClick={() => applyAiSuggestions('selected')} className="text-xs px-4 py-2 rounded-full font-bold transition-all inline-flex items-center gap-1.5"
            style={{ background: 'rgba(225,29,72,0.12)', border: '1px solid rgba(225,29,72,0.3)', color: '#f87171' }}>
            <Wand2 size={13} /> Apply AI
          </button>
          <button onClick={() => setSelected(new Set())} className="text-xs px-3 py-2 rounded-full transition-all hover:bg-white/5"
            style={{ color: 'var(--text-2)' }}>Clear</button>
        </div>
      )}

      {alerts.length > 0 && (
        <p className="text-xs text-center mt-6" style={{ color: 'var(--text-4)' }}>
          <kbd>/</kbd> search · <kbd>J</kbd>/<kbd>K</kbd> navigate · <kbd>Enter</kbd> expand · <kbd>?</kbd> shortcuts
        </p>
      )}

      {drawerAlert && (
        <DetailDrawer alert={drawerAlert} onClose={() => setDrawerAlert(null)} verdict={verdicts[drawerAlert.alert_id]} submitVerdict={handleVerdict}
          sessionId={session?.session_id && !session.session_id.startsWith('demo-') ? session.session_id : null} />
      )}
    </div>
  )
}
