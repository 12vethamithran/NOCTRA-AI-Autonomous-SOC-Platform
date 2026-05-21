import React, { useEffect, useState } from 'react'
import { Swords, Loader2, ShieldX, Crosshair, ListChecks } from 'lucide-react'
import { getChainNarrative } from '../api/client'

const SEV_COLOR = {
  CRITICAL: '#ff0000', HIGH: '#f87171', MEDIUM: '#fb7185', LOW: '#9ca3af',
}

export default function ChainNarrative({ sessionId }) {
  const [loading, setLoading] = useState(true)
  const [data, setData] = useState(null)

  useEffect(() => {
    if (!sessionId || sessionId.startsWith('demo-')) { setLoading(false); return }
    getChainNarrative(sessionId)
      .then(({ data }) => setData(data.narrative))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [sessionId])

  if (loading) return (
    <div className="flex items-center gap-2 text-sm py-6" style={{ color: 'var(--text-3)' }}>
      <Loader2 size={16} className="animate-spin" /> Correlating attack story…
    </div>
  )

  if (!data || !data.has_attack_chain) return (
    <div className="flex items-center gap-2 text-sm py-4" style={{ color: 'var(--text-3)' }}>
      <ShieldX size={16} /> {data?.narrative || 'No correlated attack chain detected.'}
    </div>
  )

  const sev = SEV_COLOR[data.severity_assessment] || '#9ca3af'

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
          style={{ background: 'rgba(225,29,72,0.12)', border: '1px solid rgba(225,29,72,0.25)' }}
        >
          <Swords size={20} style={{ color: 'var(--accent)' }} />
        </div>
        <div>
          <p className="text-base font-extrabold text-white">{data.campaign_name}</p>
          <div className="flex items-center gap-2 mt-0.5 text-xs">
            <span className="font-bold" style={{ color: sev }}>{data.severity_assessment}</span>
            {data.primary_actor_entity && data.primary_actor_entity !== '—' && (
              <span style={{ color: 'var(--text-3)' }}>· actor: <span className="font-mono text-white">{data.primary_actor_entity}</span></span>
            )}
            {data.ai_generated === false && (
              <span style={{ color: 'var(--text-4)' }}>· heuristic</span>
            )}
          </div>
        </div>
      </div>

      <p className="text-sm leading-relaxed" style={{ color: 'var(--text-1)' }}>{data.narrative}</p>

      {data.stages?.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Crosshair size={14} style={{ color: 'var(--accent)' }} />
            <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Attack stages</p>
          </div>
          <div className="space-y-2">
            {data.stages.map((s, i) => (
              <div
                key={i}
                className="px-3 py-2.5 rounded-xl"
                style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-bold text-white">{s.stage}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded" style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}>{s.mitre_tactic}</span>
                </div>
                {s.evidence && <p className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>{s.evidence}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      {data.containment_recommendations?.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <ListChecks size={14} style={{ color: 'var(--accent)' }} />
            <p className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Containment</p>
          </div>
          <div className="space-y-1.5">
            {data.containment_recommendations.map((r, i) => (
              <div key={i} className="text-sm px-3 py-2 rounded-xl" style={{ background: 'rgba(225,29,72,0.06)', border: '1px solid rgba(225,29,72,0.2)', color: 'var(--text-1)' }}>{r}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
