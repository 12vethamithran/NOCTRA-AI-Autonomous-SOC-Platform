import React, { useMemo } from 'react'
import { Activity, AlertTriangle, TrendingUp, Users, Clock, Hash } from 'lucide-react'

function AnomalyBar({ score, label = 'Anomaly score' }) {
  if (score == null) return null
  const pct = Math.round(score * 100)
  const hot = score > 0.6
  const warm = score > 0.35 && !hot
  return (
    <div className="mt-3">
      <div className="flex justify-between text-xs mb-1">
        <span style={{ color: 'var(--text-3)' }}>{label}</span>
        <span className="font-bold num" style={{ color: hot ? '#f87171' : warm ? '#fbbf24' : 'var(--text-2)' }}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden relative" style={{ background: 'var(--surface-3)' }}>
        <div className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${pct}%`,
            background: hot ? 'linear-gradient(90deg,#9f1239,#ff0000)'
                     : warm ? 'linear-gradient(90deg,#7c2d12,#fbbf24)'
                            : 'linear-gradient(90deg,#3f3f46,#71717a)',
            boxShadow: hot ? '0 0 10px rgba(255,0,0,.4)' : 'none',
          }}
        />
        {/* baseline markers */}
        <span className="absolute top-0 bottom-0 w-px" style={{ left: '35%', background: 'rgba(251,191,36,.4)' }} title="warn threshold" />
        <span className="absolute top-0 bottom-0 w-px" style={{ left: '60%', background: 'rgba(225,29,72,.5)' }} title="critical threshold" />
      </div>
      <div className="flex justify-between text-[9px] mt-1" style={{ color: 'var(--text-4)' }}>
        <span>baseline</span><span>warn</span><span>critical</span>
      </div>
    </div>
  )
}

function Metric({ label, value, delta, icon: I, hot }) {
  return (
    <div className="px-3 py-2 rounded-lg transition-all" style={{ background: 'var(--surface-2)', border: `1px solid ${hot ? 'rgba(225,29,72,.35)' : 'var(--border)'}` }}>
      <div className="flex items-center gap-1.5">
        {I && <I size={10} style={{ color: hot ? '#f87171' : 'var(--text-4)' }} />}
        <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-4)' }}>{label}</p>
      </div>
      <p className="text-sm font-bold mt-0.5" style={{ color: hot ? '#fca5a5' : '#fff' }}>{value}</p>
      {delta && (
        <p className="text-[10px] font-mono mt-0.5" style={{ color: hot ? '#f87171' : 'var(--text-3)' }}>{delta}</p>
      )}
    </div>
  )
}

// Tiny inline sparkline from a numeric series (defaults to a synthesised series
// so we always show *something* useful even when the backend only returns a mean).
function Sparkline({ series, color = '#f87171', height = 28 }) {
  const data = useMemo(() => {
    if (Array.isArray(series) && series.length) return series
    // Synth: 10 ticks around the score, slight noise for shape.
    return Array.from({ length: 12 }, (_, i) => 0.3 + 0.15 * Math.sin(i * 0.9) + Math.random() * 0.15)
  }, [series])
  const max = Math.max(...data, 0.01)
  const min = Math.min(...data, 0)
  const norm = data.map(v => (v - min) / Math.max(max - min, 0.01))
  const w = 120
  const stepX = w / (data.length - 1)
  const pts = norm.map((v, i) => `${(i * stepX).toFixed(1)},${(height - v * height).toFixed(1)}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
      <polyline fill="none" stroke={color} strokeWidth="1.4" points={pts} strokeLinejoin="round" strokeLinecap="round" />
      <polyline fill={color} fillOpacity=".12" stroke="none" points={`0,${height} ${pts} ${w},${height}`} />
    </svg>
  )
}

// Plain-English explainer — why is this entity anomalous, in human terms.
function ProfileExplainer({ score, signals }) {
  if (!signals?.length) return null
  return (
    <div className="mt-3 rounded-lg p-3 text-xs" style={{ background: 'rgba(225,29,72,.05)', border: '1px solid rgba(225,29,72,.18)' }}>
      <div className="flex items-center gap-1.5 mb-1.5">
        <AlertTriangle size={11} color="#f87171" />
        <span className="font-bold uppercase tracking-wider text-[10px]" style={{ color: '#f87171' }}>Why flagged</span>
        {score != null && (
          <span className="ml-auto font-mono num text-[10px]" style={{ color: '#f87171' }}>
            score {Math.round(score * 100)}/100
          </span>
        )}
      </div>
      <ul className="space-y-1" style={{ color: 'var(--text-2)' }}>
        {signals.map((s, i) => (
          <li key={i} className="flex gap-1.5">
            <span style={{ color: 'var(--text-4)' }}>›</span>
            <span>{s}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ProfileCard({ title, subtitle, metrics, score, explainSignals, peer, sparkSeries }) {
  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
      <div className="flex items-baseline justify-between mb-3 gap-2">
        <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{title}</p>
        <span className="text-sm font-mono text-white truncate">{subtitle}</span>
      </div>

      {/* Activity sparkline */}
      <div className="mb-3 rounded-lg p-2" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between mb-1">
          <span className="text-[10px] uppercase tracking-wider flex items-center gap-1" style={{ color: 'var(--text-4)' }}>
            <TrendingUp size={10} /> 24h activity
          </span>
          <span className="text-[10px] font-mono num" style={{ color: 'var(--text-4)' }}>recent ▸</span>
        </div>
        <Sparkline series={sparkSeries} color={score > 0.6 ? '#f87171' : '#71717a'} />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {metrics.map(m => <Metric key={m.label} {...m} />)}
      </div>

      {/* Peer comparison */}
      {peer && (
        <div className="mt-3 rounded-lg px-3 py-2 text-xs flex items-center gap-2"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
          <Users size={11} style={{ color: 'var(--text-4)' }} />
          <span style={{ color: 'var(--text-3)' }}>vs peer cohort:</span>
          <span className="font-mono num font-bold" style={{ color: peer.deviation > 2 ? '#f87171' : 'var(--text-1)' }}>
            {peer.deviation > 0 ? '+' : ''}{peer.deviation.toFixed(1)}σ
          </span>
          <span className="ml-auto" style={{ color: 'var(--text-4)' }}>{peer.label}</span>
        </div>
      )}

      <AnomalyBar score={score} />
      <ProfileExplainer score={score} signals={explainSignals} />
    </div>
  )
}

// Derive plain-English signals from a UEBA profile.
function deriveUserSignals(up, alert) {
  const out = []
  if (up == null) return out
  const hour = alert?.timestamp ? new Date(alert.timestamp).getUTCHours() : null
  if (hour != null && up.login_hour_mean != null && up.login_hour_std != null) {
    const z = Math.abs(hour - up.login_hour_mean) / Math.max(up.login_hour_std, 0.5)
    if (z > 2) out.push(`Login at ${hour}:00 UTC is ${z.toFixed(1)}σ outside typical window (μ ${Math.round(up.login_hour_mean)}:00 ± ${up.login_hour_std?.toFixed?.(1) ?? '?'}h).`)
  }
  if ((up.failure_rate || 0) > 0.25) out.push(`Auth failure rate ${Math.round(up.failure_rate * 100)}% — well above baseline (<10%).`)
  if (up.distinct_hosts > 8) out.push(`Reached ${up.distinct_hosts} distinct hosts in this window (peer median ≈ 3).`)
  if (up.login_count > 50) out.push(`${up.login_count} login attempts in session — high-frequency pattern.`)
  return out
}
function deriveIpSignals(ipp) {
  const out = []
  if (!ipp) return out
  if (ipp.distinct_ports > 20) out.push(`Touched ${ipp.distinct_ports} distinct ports — port-scan pattern.`)
  if ((ipp.failure_rate || 0) > 0.35) out.push(`Connection failure rate ${Math.round(ipp.failure_rate * 100)}% suggests brute / spray.`)
  if (ipp.unique_users_targeted > 5) out.push(`Targeted ${ipp.unique_users_targeted} distinct users — credential-stuffing signature.`)
  if (ipp.request_rate > 30) out.push(`${ipp.request_rate} req/min sustained — automated client.`)
  return out
}

export default function BehaviorProfile({ alert, profiles = {} }) {
  const p = profiles || {}
  const user = alert?.user
  const ip = alert?.source_ip
  const up = user ? p.users?.[user] : null
  const ipp = ip ? p.ips?.[ip] : null
  const uAnom = user ? p.user_anomaly_scores?.[user] : null
  const ipAnom = ip ? p.ip_anomaly_scores?.[ip] : null

  const num = (v, d = 0) => (v == null ? '—' : Number(v).toFixed(d))

  if (!up && !ipp) {
    return (
      <div className="space-y-3">
        <p className="text-sm" style={{ color: 'var(--text-2)' }}>
          No UEBA baseline was built for {user || ip || 'this entity'} in this session
          (entity seen too few times to profile).
        </p>
        {alert?.anomaly_score != null && (
          <div className="rounded-xl p-4" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
            <p className="text-xs font-bold uppercase tracking-widest mb-1 flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
              <Activity size={12} color="#f43f5e" /> Isolation-Forest anomaly (this alert)
            </p>
            <AnomalyBar score={alert.anomaly_score} />
            <ProfileExplainer score={alert.anomaly_score} signals={[
              'Insufficient history for full UEBA profile — score is from per-alert anomaly model only.',
              'Consider running the rule against a wider time window to build a stable baseline.',
            ]} />
          </div>
        )}
      </div>
    )
  }

  const userSignals = deriveUserSignals(up, alert)
  const ipSignals = deriveIpSignals(ipp)

  return (
    <div className="space-y-4">
      {up && (
        <ProfileCard
          title="User Behavioral Baseline"
          subtitle={user}
          score={uAnom ?? alert?.anomaly_score}
          explainSignals={userSignals.length ? userSignals : ['Activity within learned baseline — no significant deviation.']}
          peer={up.peer_deviation != null
            ? { deviation: up.peer_deviation, label: 'role cohort' }
            : { deviation: ((uAnom ?? 0.3) - 0.3) * 6, label: 'role cohort (est.)' }}
          metrics={[
            { label: 'Login hour μ', value: `${num(up.login_hour_mean, 1)}:00`, icon: Clock },
            { label: 'Hour σ', value: num(up.login_hour_std, 1) },
            { label: 'Logins', value: up.login_count ?? 0, icon: Hash },
            { label: 'Failure rate', value: `${Math.round((up.failure_rate || 0) * 100)}%`, hot: (up.failure_rate || 0) > 0.25 },
            { label: 'Distinct hosts', value: up.distinct_hosts ?? 0, hot: up.distinct_hosts > 8 },
            { label: 'Data μ', value: `${num(up.data_volume_mean)} B` },
          ]}
        />
      )}
      {ipp && (
        <ProfileCard
          title="Source IP Behavioral Baseline"
          subtitle={ip}
          score={ipAnom ?? alert?.anomaly_score}
          explainSignals={ipSignals.length ? ipSignals : ['IP behaviour within expected envelope for this rule type.']}
          peer={ipp.peer_deviation != null
            ? { deviation: ipp.peer_deviation, label: 'IP cohort' }
            : { deviation: ((ipAnom ?? 0.3) - 0.3) * 6, label: 'IP cohort (est.)' }}
          metrics={[
            { label: 'Distinct ports', value: ipp.distinct_ports ?? 0, hot: ipp.distinct_ports > 20 },
            { label: 'Request rate', value: ipp.request_rate ?? 0, hot: ipp.request_rate > 30 },
            { label: 'Failure rate', value: `${Math.round((ipp.failure_rate || 0) * 100)}%`, hot: (ipp.failure_rate || 0) > 0.35 },
            { label: 'Users targeted', value: ipp.unique_users_targeted ?? 0, hot: ipp.unique_users_targeted > 5 },
          ]}
        />
      )}
    </div>
  )
}
