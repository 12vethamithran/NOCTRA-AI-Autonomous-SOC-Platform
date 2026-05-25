/**
 * useApiHealth() — single source of truth for backend reachability.
 *
 * Returns one of: 'checking' | 'online' | 'degraded' | 'offline'.
 *
 * Hits {VITE_API_URL}/health (falls back to /api/health in dev where Vite
 * proxies). Retries 3× with a 60s timeout each so Render's free-tier cold
 * start (30–50 s) doesn't register as "offline" the way the old single-shot
 * 3-second probe in Upload.jsx did.
 *
 * Re-polls every 60 s while the tab is visible.
 */
import { useEffect, useState } from 'react'

const POLL_MS = 60_000

export default function useApiHealth() {
  const [status, setStatus] = useState('checking')

  useEffect(() => {
    const base = import.meta.env.VITE_API_URL ?? '/api'
    let cancelled = false
    let timer

    const probe = async () => {
      if (cancelled) return
      setStatus(s => (s === 'online' ? 'checking' : s))
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(60_000) })
          if (cancelled) return
          setStatus(r.ok ? 'online' : 'degraded')
          return
        } catch {
          if (cancelled) return
          if (attempt < 2) {
            await new Promise(res => setTimeout(res, 5_000))
          }
        }
      }
      if (!cancelled) setStatus('offline')
    }

    probe()
    timer = setInterval(probe, POLL_MS)
    const onVis = () => { if (document.visibilityState === 'visible') probe() }
    document.addEventListener('visibilitychange', onVis)

    return () => {
      cancelled = true
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [])

  return status
}
