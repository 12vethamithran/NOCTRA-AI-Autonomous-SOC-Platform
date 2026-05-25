import { useState, useEffect } from 'react'
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  Shield, Upload, ShieldAlert, Crosshair, SlidersHorizontal,
  LayoutDashboard, Search as SearchIcon, Command, Activity,
  Wifi, WifiOff, AlertTriangle, X as XIcon, Keyboard,
} from 'lucide-react'
import { useSession } from '../App'
import { deleteSession } from '../api/client'
import toast from 'react-hot-toast'
import BackgroundCanvas from './BackgroundCanvas'
import CommandPalette from './CommandPalette'
import useApiHealth from '../utils/useApiHealth'

function useClock() {
  const [t, setT] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return t
}

const SHORTCUTS = [
  { keys: ['⌘', 'K'],  desc: 'Command palette' },
  { keys: ['G', 'T'],  desc: 'Go to Triage' },
  { keys: ['G', 'H'],  desc: 'Go to Hunt' },
  { keys: ['G', 'R'],  desc: 'Go to Rules' },
  { keys: ['G', 'D'],  desc: 'Go to Dashboard' },
  { keys: ['G', 'U'],  desc: 'Go to Upload' },
  { keys: ['/'],       desc: 'Focus search (Triage)' },
  { keys: ['J', 'K'],  desc: 'Navigate alerts' },
  { keys: ['Enter'],   desc: 'Expand alert row' },
  { keys: ['T'],       desc: 'Quick True Positive' },
  { keys: ['F'],       desc: 'Quick False Positive' },
  { keys: ['?'],       desc: 'Toggle this panel' },
]

const NAV_ITEMS = [
  { to: '/',          label: 'Overview',  end: true, icon: LayoutDashboard,   needsSession: false },
  { to: '/upload',    label: 'Upload',               icon: Upload,            needsSession: false },
  { to: '/triage',    label: 'Triage',               icon: ShieldAlert,       needsSession: true  },
  { to: '/hunt',      label: 'Hunt',                 icon: Crosshair,         needsSession: true  },
  { to: '/rules',     label: 'Rules',                icon: SlidersHorizontal, needsSession: true  },
  { to: '/dashboard', label: 'Dashboard',            icon: LayoutDashboard,   needsSession: true  },
]

const CRUMB_MAP = {
  '/':           ['Overview'],
  '/upload':     ['Upload'],
  '/triage':     ['Triage Queue'],
  '/hunt':       ['Threat Hunt'],
  '/rules':      ['Detection Rules'],
  '/dashboard':  ['Operations Dashboard'],
}

export default function Layout() {
  const { session, setSession } = useSession()
  const navigate  = useNavigate()
  const location  = useLocation()
  const clock     = useClock()
  const health    = useApiHealth()
  const [showHelp, setShowHelp] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)

  const verdicts     = session?.verdicts ?? {}
  const alerts       = session?.alerts   ?? []
  const tpCount      = Object.values(verdicts).filter(v => v.decision === 'TP').length
  const pendingCount = alerts.length - Object.keys(verdicts).length
  const criticalPending = alerts.filter(a => a.severity === 'CRITICAL' && !verdicts[a.alert_id]).length

  // Threat level derived from pending criticals and confirmed incidents
  const threatLevel = criticalPending > 0 || tpCount >= 5 ? 'SEVERE'
                    : tpCount > 0 || pendingCount >= 5    ? 'ELEVATED'
                    : pendingCount > 0                    ? 'GUARDED'
                                                          : 'LOW'
  const threatColor = {
    SEVERE:   { fg: '#ff4d4d', bg: 'rgba(255,77,77,.10)',  bd: 'rgba(255,77,77,.40)' },
    ELEVATED: { fg: '#f97316', bg: 'rgba(249,115,22,.10)', bd: 'rgba(249,115,22,.35)' },
    GUARDED:  { fg: '#fbbf24', bg: 'rgba(251,191,36,.08)', bd: 'rgba(251,191,36,.30)' },
    LOW:      { fg: '#4ade80', bg: 'rgba(74,222,128,.08)', bd: 'rgba(74,222,128,.30)' },
  }[threatLevel]

  useEffect(() => {
    let gPending = false, gTimer = null
    const handler = (e) => {
      const tag = e.target.tagName
      const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'

      // Cmd+K / Ctrl+K always works
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(o => !o)
        return
      }

      if (isInput) return
      if (e.key === '?') { setShowHelp(h => !h); return }
      if (e.key === 'Escape') { setShowHelp(false); setPaletteOpen(false); return }
      if (e.key.toLowerCase() === 'g') {
        gPending = true
        clearTimeout(gTimer)
        gTimer = setTimeout(() => { gPending = false }, 800)
        return
      }
      if (gPending) {
        gPending = false; clearTimeout(gTimer)
        const k = e.key.toLowerCase()
        if (k === 't') navigate('/triage')
        if (k === 'd') navigate('/dashboard')
        if (k === 'u') navigate('/upload')
        if (k === 'h') navigate('/hunt')
        if (k === 'r') navigate('/rules')
        if (k === 'o') navigate('/')
      }
    }
    const toggleHelp = () => setShowHelp(h => !h)
    window.addEventListener('keydown', handler)
    window.addEventListener('toggle-shortcuts', toggleHelp)
    return () => {
      window.removeEventListener('keydown', handler)
      window.removeEventListener('toggle-shortcuts', toggleHelp)
    }
  }, [navigate])

  const handleClear = async () => {
    if (!session) return
    try { await deleteSession(session.session_id) } catch {}
    setSession(null)
    navigate('/')
    toast.success('Session cleared — all data wiped from memory.')
  }

  const HEALTH = {
    checking: { icon: Activity,       dot: 'bg-amber-400',   fg: 'text-amber-300',   text: 'Waking engine…' },
    online:   { icon: Wifi,           dot: 'bg-emerald-400', fg: 'text-emerald-300', text: 'Engine Online' },
    degraded: { icon: AlertTriangle,  dot: 'bg-amber-500',   fg: 'text-amber-300',   text: 'Degraded' },
    offline:  { icon: WifiOff,        dot: 'bg-red-500',     fg: 'text-red-300',     text: 'Engine Offline' },
  }
  const h = HEALTH[health]
  const HIcon = h.icon
  const hours   = clock.toISOString().slice(11, 19)
  const dateStr = clock.toUTCString().slice(5, 16)

  const crumbs = CRUMB_MAP[location.pathname] || ['Investigation']

  return (
    <div className="min-h-screen flex flex-col" style={{ background: 'var(--bg)', position: 'relative' }}>
      <BackgroundCanvas />

      {/* ── Top micro-bar (v4 — bold-typography refinement) ── */}
      <div className="topbar-v4 px-4 py-2 text-xs flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 overflow-hidden">
          <span className={`topbar-chip topbar-chip-dot ${health === 'online' ? 'text-emerald-300' : health === 'offline' ? 'text-red-300' : 'text-amber-300'}`}
            style={{ background: 'rgba(255,255,255,.02)', borderColor: 'rgba(255,255,255,.06)' }}>
            <HIcon size={9} />
            <span className="hidden sm:inline">{h.text.toUpperCase()}</span>
          </span>
          <span className="hidden sm:flex items-center gap-2 shrink-0">
            <span className="topbar-brand">N<span className="o">O</span>CTRA</span>
            <span className="topbar-sep">/</span>
            <span className="text-[10px] tracking-[0.22em] uppercase font-semibold" style={{ color: 'var(--text-3)' }}>Autonomous&nbsp;SOC</span>
            <span className="topbar-chip topbar-chip-accent">v3.2</span>
          </span>
          <span className="topbar-chip topbar-chip-dot"
            style={{ color: threatColor.fg, background: threatColor.bg, borderColor: threatColor.bd }}>
            THREAT: {threatLevel}
          </span>
          {tpCount > 0 && (
            <span className="topbar-chip topbar-chip-dot hidden md:inline-flex"
              style={{ color: '#f87171', background: 'rgba(239,68,68,0.06)', borderColor: 'rgba(239,68,68,0.25)' }}>
              {tpCount} INCIDENT{tpCount !== 1 ? 'S' : ''}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="font-mono num text-[10px] hidden md:flex items-center gap-1.5 tracking-wider" style={{ color: 'var(--text-3)' }}>
            <span style={{ color: 'var(--text-4)' }}>{dateStr}</span>
            <span style={{ color: 'var(--accent)' }}>{hours}</span>
            <span style={{ color: 'var(--text-4)' }}>UTC</span>
          </span>
          <button
            onClick={() => setPaletteOpen(true)}
            data-tip="Command palette"
            className="hidden sm:inline-flex items-center gap-1.5 border px-2 py-0.5 rounded text-[10px] transition-colors tracking-wider"
            style={{ borderColor: 'var(--border-2)', color: 'var(--text-3)' }}
          >
            <Command size={10} />K
          </button>
          <button
            onClick={() => setShowHelp(h => !h)}
            data-tip="Keyboard shortcuts"
            className="border px-1.5 py-0.5 rounded font-mono transition-colors text-zinc-600 hover:text-zinc-300"
            style={{ borderColor: 'var(--border-2)' }}
          >?</button>
        </div>
      </div>

      {/* ── Main nav ── */}
      <header
        className="sticky top-0 z-50 border-b glass elev-3"
        style={{ borderColor: 'var(--border)' }}
      >
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center gap-4">

          {/* Logo */}
          <NavLink to="/" className="flex items-center gap-2.5 shrink-0 group">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center transition-all group-hover:scale-105 relative"
              style={{ filter: 'drop-shadow(0 0 10px rgba(225,29,72,.35))' }}>
              <img src="/noctra-logo.svg" alt="Noctra" width={32} height={32} className="select-none" draggable="false" />
              <span className="absolute inset-0 rounded-xl pointer-events-none"
                style={{ boxShadow: 'inset 0 0 12px rgba(225,29,72,.18)' }} />
            </div>
            <div className="hidden sm:block">
              <p className="text-[15px] font-extrabold text-white leading-tight tracking-[0.08em]">
                N<span style={{ color: 'var(--accent)' }}>O</span>CTRA <span className="aurora-text">AI</span>
              </p>
              <p className="text-[9px] font-bold tracking-[0.24em] uppercase leading-tight flex items-center gap-1.5"
                style={{ color: 'var(--accent)' }}>
                <span>Autonomous SOC</span>
                <span style={{ color: 'var(--border-3)' }}>·</span>
                <span className="num" style={{ color: 'var(--text-4)' }}>v3.2</span>
              </p>
            </div>
          </NavLink>

          <div className="w-px h-6 hidden sm:block shrink-0" style={{ background: 'var(--border-2)' }} />

          {/* Nav */}
          <nav className="flex items-center gap-0.5">
            {NAV_ITEMS.filter(n => !n.needsSession || session).map(({ to, label, end, icon: Icon }) => {
              const badge = to === '/triage' && pendingCount > 0 ? pendingCount : null
              return (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `nav-pill relative inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                      isActive ? 'text-white' : 'text-zinc-400 hover:text-zinc-100 hover:bg-white/[0.04]'
                    }`
                  }
                  style={({ isActive }) => isActive ? {
                    background: 'rgba(225,29,72,0.10)',
                    boxShadow: '0 0 0 1px rgba(225,29,72,0.30), inset 0 1px 0 rgba(255,255,255,0.04)',
                    color: '#f87171',
                  } : {}}
                  data-active={location.pathname === to ? 'true' : 'false'}
                >
                  <Icon size={14} />
                  {label}
                  {badge != null && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full leading-none num"
                      style={{ background: '#f43f5e', color: 'white', boxShadow: '0 0 8px rgba(244,63,94,.6)' }}>
                      {badge}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </nav>

          {/* Right side */}
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => setPaletteOpen(true)}
              className="hidden md:inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border transition-colors whitespace-nowrap shrink-0"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border-2)', color: 'var(--text-3)' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(225,29,72,.35)'; e.currentTarget.style.color = 'var(--text-1)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-2)'; e.currentTarget.style.color = 'var(--text-3)' }}
            >
              <SearchIcon size={12} />
              <span>Search</span>
              <kbd>⌘K</kbd>
            </button>
            {session ? (
              <>
                <span
                  className="hidden lg:flex items-center gap-2 text-xs num font-mono px-2.5 py-1 rounded"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-3)' }}
                >
                  <span className="dot-live" />
                  {session.session_id.slice(0, 8)}
                </span>
                <span
                  className="text-xs px-2.5 py-1 rounded-full border font-medium hidden sm:inline-block whitespace-nowrap shrink-0"
                  style={{ background: 'rgba(34,197,94,0.08)', borderColor: 'rgba(34,197,94,0.25)', color: '#4ade80' }}
                >
                  {alerts.length} alerts
                </span>
                <button
                  onClick={handleClear}
                  className="text-xs px-2.5 py-1 rounded-lg border transition-all hover:bg-red-900/20 inline-flex items-center gap-1"
                  style={{ color: 'rgba(248,113,113,0.7)', borderColor: 'rgba(225,29,72,0.2)' }}
                >
                  <XIcon size={11} /> Clear
                </button>
              </>
            ) : (
              <span className="text-xs" style={{ color: 'var(--text-3)' }}>No active session</span>
            )}
          </div>
        </div>

        {/* Breadcrumbs */}
        {location.pathname !== '/' && (
          <div className="max-w-7xl mx-auto px-4 py-1.5 text-[11px] flex items-center" style={{ color: 'var(--text-4)' }}>
            <NavLink to="/" className="hover:text-white transition-colors">Home</NavLink>
            <span className="crumb-sep">/</span>
            {crumbs.map((c, i) => (
              <span key={i} className={i === crumbs.length - 1 ? 'text-white font-semibold' : ''}>
                {c}{i < crumbs.length - 1 && <span className="crumb-sep">/</span>}
              </span>
            ))}
          </div>
        )}
      </header>

      {/* ── Content ── */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        <Outlet />
      </main>

      {/* ── Footer ── */}
      <footer className="border-t no-print" style={{ background: 'rgba(8,8,9,0.6)', borderColor: 'var(--border)' }}>
        <div className="max-w-7xl mx-auto px-4 py-2.5 flex items-center justify-between text-xs" style={{ color: 'var(--text-4)' }}>
          <span className="flex items-center gap-2">
            <span className="dot-live" />
            NOCTRA AI · Storageless · Session data lives only in RAM
          </span>
          <span className="hidden sm:flex items-center gap-2">
            <kbd>⌘K</kbd> palette · <kbd>?</kbd> shortcuts
          </span>
        </div>
      </footer>

      {/* ── Command Palette ── */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        hasSession={!!session}
        onClear={handleClear}
      />

      {/* ── Shortcuts modal ── */}
      {showHelp && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center fade-in"
          style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)' }}
          onClick={() => setShowHelp(false)}
        >
          <div
            className="rounded-2xl p-6 w-full max-w-md shadow-2xl slide-down elev-4 gradient-border"
            style={{ background: 'var(--surface)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg icon-3d-red flex items-center justify-center">
                  <Keyboard size={16} color="#f43f5e" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">Keyboard Shortcuts</h2>
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>Power-user navigation</p>
                </div>
              </div>
              <button
                onClick={() => setShowHelp(false)}
                className="transition-colors hover:text-white"
                style={{ color: 'var(--text-3)' }}
              ><XIcon size={18} /></button>
            </div>

            <div className="grid grid-cols-2 gap-2 mb-4">
              {SHORTCUTS.map(({ keys, desc }) => (
                <div
                  key={keys.join('')}
                  className="flex flex-col justify-center gap-1.5 px-3 py-2.5 rounded-lg transition-colors hover:bg-white/[0.03] border"
                  style={{ borderColor: 'var(--border-2)' }}
                >
                  <div className="flex items-center gap-1">
                    {keys.map((k, i) => (
                      <span key={i} className="flex items-center gap-1">
                        {i > 0 && <span className="text-[10px]" style={{ color: 'var(--text-4)' }}>then</span>}
                        <kbd>{k}</kbd>
                      </span>
                    ))}
                  </div>
                  <span className="text-xs font-medium" style={{ color: 'var(--text-2)' }}>{desc}</span>
                </div>
              ))}
            </div>

            <div
              className="text-xs pt-4 border-t"
              style={{ color: 'var(--text-4)', borderColor: 'var(--border)' }}
            >
              Shortcuts inactive when a text input is focused.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
