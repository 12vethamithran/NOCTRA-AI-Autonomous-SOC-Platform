import React from 'react'

export default function ShapChart({ shapFeatures = [] }) {
  if (!shapFeatures?.length) {
    return <p className="text-sm" style={{ color: 'var(--text-3)' }}>No SHAP feature attributions available for this alert.</p>
  }

  const rows = shapFeatures
    .map(f => ({
      name: String(f.feature || '').replace(/_/g, ' '),
      contribution: Math.abs(Number(f.contribution) || 0),
      direction: f.direction,
      value: f.value,
    }))
    .sort((a, b) => b.contribution - a.contribution)

  const max = Math.max(...rows.map(r => r.contribution), 0.0001)

  return (
    <div className="space-y-3">
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>
        How each feature pushed the model's True-Positive probability for this alert.
      </p>
      <div className="space-y-2.5">
        {rows.map((r, i) => {
          const pct = (r.contribution / max) * 100
          const up = r.direction === 'positive'
          return (
            <div key={i}>
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="font-medium capitalize" style={{ color: 'var(--text-1)' }}>
                  {r.name}
                  {r.value != null && (
                    <span className="ml-2 font-mono" style={{ color: 'var(--text-4)' }}>
                      ({String(r.value).slice(0, 18)})
                    </span>
                  )}
                </span>
                <span className="font-mono tabular-nums" style={{ color: up ? '#f87171' : 'var(--text-3)' }}>
                  {up ? '+' : '−'}{r.contribution.toFixed(3)}
                </span>
              </div>
              <div className="h-2.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${Math.max(pct, 3)}%`,
                    background: up
                      ? 'linear-gradient(90deg,#9f1239,#e11d48)'
                      : 'linear-gradient(90deg,#3f3f46,#71717a)',
                  }}
                />
              </div>
            </div>
          )
        })}
      </div>
      <div className="flex items-center gap-4 text-[11px] pt-1" style={{ color: 'var(--text-4)' }}>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#e11d48' }} /> raises TP probability
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#71717a' }} /> lowers TP probability
        </span>
      </div>
    </div>
  )
}
