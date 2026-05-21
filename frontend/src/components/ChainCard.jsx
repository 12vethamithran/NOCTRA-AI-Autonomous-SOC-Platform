import React from 'react'
import {
  Crosshair, DoorOpen, Terminal, Anchor, ArrowUpCircle,
  Network, FolderInput, Upload, Flame, Link2, ChevronRight,
} from 'lucide-react'

const STAGE_ICON = {
  Reconnaissance: Crosshair,
  'Initial Access': DoorOpen,
  Execution: Terminal,
  Persistence: Anchor,
  'Privilege Escalation': ArrowUpCircle,
  'Lateral Movement': Network,
  Collection: FolderInput,
  Exfiltration: Upload,
  Impact: Flame,
}

export default function ChainCard({ chain, onAlertClick = () => {} }) {
  if (!chain) return null

  const confidence = Math.round((chain.confidence || 0) * 100)
  const StageIcon = STAGE_ICON[chain.kill_chain_stage] || Link2

  return (
    <div
      className="rounded-2xl p-4 mb-2"
      style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: 'rgba(225,29,72,0.12)', border: '1px solid rgba(225,29,72,0.25)' }}
          >
            <StageIcon size={18} style={{ color: 'var(--accent)' }} />
          </div>
          <div className="min-w-0">
            <h4 className="font-bold text-sm text-white truncate">{chain.name}</h4>
            <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
              {chain.kill_chain_stage}
            </span>
          </div>
        </div>
        {chain.mitre_group && (
          <span
            className="text-[10px] px-2 py-1 rounded-full font-bold shrink-0"
            style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}
          >
            {chain.mitre_group}
          </span>
        )}
      </div>

      <p className="text-xs mb-3" style={{ color: 'var(--text-2)' }}>{chain.description}</p>

      <div className="mb-3">
        <div className="flex justify-between text-[11px] mb-1">
          <span style={{ color: 'var(--text-3)' }}>Correlation confidence</span>
          <span className="font-bold text-white">{confidence}%</span>
        </div>
        <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${confidence}%`,
              background: confidence >= 75
                ? 'linear-gradient(90deg,#9f1239,#ff0000)'
                : 'linear-gradient(90deg,#9f1239,#e11d48)',
            }}
          />
        </div>
      </div>

      {chain.matched_alerts?.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {chain.matched_alerts.map((alertId, i) => (
            <React.Fragment key={alertId}>
              {i > 0 && <ChevronRight size={12} style={{ color: 'var(--text-4)' }} />}
              <button
                onClick={() => onAlertClick(alertId)}
                className="text-[10px] font-mono px-2 py-1 rounded-lg transition-all"
                style={{ background: 'rgba(225,29,72,0.1)', border: '1px solid rgba(225,29,72,0.25)', color: '#f87171' }}
              >
                {alertId.substring(0, 8)}
              </button>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  )
}
