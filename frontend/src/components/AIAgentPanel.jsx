import React, { useState } from 'react'
import {
  Bot, Sparkles, ShieldAlert, ShieldCheck, ArrowUpCircle,
  ListChecks, Search, Lightbulb, Loader2,
} from 'lucide-react'
import { agentInvestigate } from '../api/client'
import toast from 'react-hot-toast'

const VERDICT = {
  TP:       { label: 'True Positive',  Icon: ShieldAlert,    color: '#f87171', bg: 'rgba(239,68,68,0.1)',  border: 'rgba(239,68,68,0.3)' },
  FP:       { label: 'False Positive', Icon: ShieldCheck,    color: '#9ca3af', bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.3)' },
  ESCALATE: { label: 'Escalate',       Icon: ArrowUpCircle,  color: '#fb7185', bg: 'rgba(244,63,94,0.12)', border: 'rgba(244,63,94,0.35)' },
}

function Block({ icon: Icon, title, children }) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <Icon size={14} style={{ color: 'var(--accent)' }} />
        <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{title}</p>
      </div>
      {children}
    </div>
  )
}

export default function AIAgentPanel({ sessionId, alertId, onPivot }) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const run = async () => {
    if (!sessionId || sessionId.startsWith('demo-')) {
      toast.error('AI agent needs a live backend session')
      return
    }
    setLoading(true)
    try {
      const { data } = await agentInvestigate(sessionId, alertId, true)
      setResult(data.investigation)
      toast.success('Autonomous investigation complete')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Agent investigation failed')
    } finally {
      setLoading(false)
    }
  }

  if (!result) {
    return (
      <div className="text-center py-10">
        <div
          className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
          style={{ background: 'rgba(225,29,72,0.12)', border: '1px solid rgba(225,29,72,0.25)' }}
        >
          <Bot size={26} style={{ color: 'var(--accent)' }} />
        </div>
        <p className="text-sm font-semibold text-white mb-1">Autonomous Investigation Agent</p>
        <p className="text-xs mb-5 max-w-md mx-auto" style={{ color: 'var(--text-3)' }}>
          The agent pulls the timeline, IOCs, related alerts, UEBA and chain signals,
          then returns a reasoned verdict with next actions and pivot hunts.
        </p>
        <button
          onClick={run}
          disabled={loading}
          className="btn-accent text-sm px-5 py-2.5 rounded-xl inline-flex items-center gap-2 disabled:opacity-50"
        >
          {loading
            ? <><Loader2 size={16} className="animate-spin" /> Investigating…</>
            : <><Sparkles size={16} /> Run AI Investigation</>}
        </button>
      </div>
    )
  }

  const v = VERDICT[result.verdict_recommendation] || VERDICT.TP
  const conf = Math.round((result.confidence || 0) * 100)

  return (
    <div className="space-y-5">
      <div
        className="rounded-2xl p-4 flex items-center gap-4"
        style={{ background: v.bg, border: `1px solid ${v.border}` }}
      >
        <v.Icon size={28} style={{ color: v.color }} />
        <div className="flex-1">
          <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>
            Recommended verdict
          </p>
          <p className="text-xl font-extrabold" style={{ color: v.color }}>{v.label}</p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-extrabold tabular-nums text-white">{conf}%</p>
          <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>
            {result.ai_generated ? 'AI confidence' : 'heuristic'}
          </p>
        </div>
      </div>

      <p className="text-sm leading-relaxed" style={{ color: 'var(--text-1)' }}>{result.summary}</p>

      {result.key_findings?.length > 0 && (
        <Block icon={Lightbulb} title="Key findings">
          <ul className="space-y-1.5">
            {result.key_findings.map((f, i) => (
              <li key={i} className="text-sm flex gap-2" style={{ color: 'var(--text-2)' }}>
                <span style={{ color: 'var(--accent)' }}>•</span>{f}
              </li>
            ))}
          </ul>
        </Block>
      )}

      {result.reasoning_steps?.length > 0 && (
        <Block icon={Bot} title="Reasoning">
          <ol className="space-y-1.5">
            {result.reasoning_steps.map((s, i) => (
              <li key={i} className="text-sm flex gap-2.5" style={{ color: 'var(--text-2)' }}>
                <span className="font-mono text-xs shrink-0 mt-0.5" style={{ color: 'var(--text-4)' }}>{i + 1}.</span>{s}
              </li>
            ))}
          </ol>
        </Block>
      )}

      {result.next_best_actions?.length > 0 && (
        <Block icon={ListChecks} title="Next best actions">
          <div className="space-y-1.5">
            {result.next_best_actions.map((a, i) => (
              <div
                key={i}
                className="text-sm px-3 py-2 rounded-xl"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-1)' }}
              >
                {a}
              </div>
            ))}
          </div>
        </Block>
      )}

      {result.pivot_hunts?.length > 0 && (
        <Block icon={Search} title="Suggested pivot hunts">
          <div className="space-y-1.5">
            {result.pivot_hunts.map((p, i) => (
              <button
                key={i}
                onClick={() => onPivot?.(p.filters)}
                className="w-full text-left text-sm px-3 py-2 rounded-xl transition-all flex items-center justify-between gap-2"
                style={{ background: 'rgba(225,29,72,0.06)', border: '1px solid rgba(225,29,72,0.2)', color: 'var(--text-1)' }}
              >
                <span>{p.description}</span>
                <Search size={14} style={{ color: 'var(--accent)' }} />
              </button>
            ))}
          </div>
        </Block>
      )}
    </div>
  )
}
