import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, Upload, ShieldAlert, Crosshair, SlidersHorizontal,
  LayoutDashboard, FileBarChart, Bot, Keyboard, LogOut, ArrowRight,
} from 'lucide-react'
import useFocusTrap from '../utils/useFocusTrap'

/**
 * Cmd+K command palette. Lazy-bound so it sits in the document tree but
 * only renders its overlay when `open`. Closing on Escape or backdrop click.
 */
export default function CommandPalette({ open, onClose, hasSession, onClear }) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef = useRef(null)
  const panelRef = useRef(null)
  useFocusTrap(open, panelRef)

  const ACTIONS = useMemo(() => ([
    { id: 'overview',  label: 'Go to Overview',        hint: 'G O',   icon: Upload,           run: () => navigate('/') },
    { id: 'upload',    label: 'Go to Upload',          hint: 'G U',   icon: Upload,           run: () => navigate('/upload') },
    hasSession && { id: 'triage',    label: 'Open Triage Queue',     hint: 'G T',   icon: ShieldAlert,      run: () => navigate('/triage') },
    hasSession && { id: 'hunt',      label: 'Open Threat Hunt',      hint: 'G H',   icon: Crosshair,        run: () => navigate('/hunt') },
    hasSession && { id: 'rules',     label: 'Rule Builder',          hint: 'G R',   icon: SlidersHorizontal, run: () => navigate('/rules') },
    hasSession && { id: 'dashboard', label: 'Operations Dashboard',  hint: 'G D',   icon: LayoutDashboard,  run: () => navigate('/dashboard') },
    hasSession && { id: 'report',    label: 'Generate Incident Report', hint: 'R', icon: FileBarChart,    run: () => navigate('/dashboard?focus=report') },
    hasSession && { id: 'ai',        label: 'Ask SOC AI Agent',      hint: 'A',     icon: Bot,              run: () => navigate('/triage?ai=1') },
    { id: 'shortcuts', label: 'Show keyboard shortcuts', hint: '?',  icon: Keyboard,         run: () => { onClose(); window.dispatchEvent(new CustomEvent('toggle-shortcuts')) } },
    hasSession && { id: 'clear', label: 'Clear session (purge memory)', hint: 'X', icon: LogOut,         run: () => onClear?.(), danger: true },
  ].filter(Boolean)), [hasSession, navigate, onClose, onClear])

  const filtered = useMemo(() => {
    if (!q.trim()) return ACTIONS
    const needle = q.toLowerCase()
    return ACTIONS.filter(a => a.label.toLowerCase().includes(needle))
  }, [q, ACTIONS])

  useEffect(() => {
    if (!open) { setQ(''); setActiveIdx(0); return }
    setTimeout(() => inputRef.current?.focus(), 30)
  }, [open])

  useEffect(() => { setActiveIdx(0) }, [q])

  useEffect(() => {
    if (!open) return
    const handler = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose(); return }
      if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, filtered.length - 1)); return }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, 0)); return }
      if (e.key === 'Enter') {
        e.preventDefault()
        const a = filtered[activeIdx]
        if (a) { a.run(); onClose() }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, filtered, activeIdx, onClose])

  if (!open) return null

  return (
    <div
      className="cmdk-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div ref={panelRef} className="cmdk-panel" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-4 border-b" style={{ borderColor: 'var(--border)' }}>
          <Search size={16} style={{ color: 'var(--text-3)' }} />
          <input
            ref={inputRef}
            className="cmdk-input"
            placeholder="Type a command, page, or action…"
            value={q}
            onChange={e => setQ(e.target.value)}
            style={{ borderBottom: 'none', padding: '14px 0' }}
          />
          <kbd className="hidden sm:inline-block">esc</kbd>
        </div>
        <div className="cmdk-list">
          {filtered.length === 0 && (
            <div className="px-4 py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              No matching commands.
            </div>
          )}
          {filtered.map((a, i) => {
            const Icon = a.icon
            return (
              <div
                key={a.id}
                data-active={i === activeIdx ? 'true' : 'false'}
                className="cmdk-item"
                onMouseEnter={() => setActiveIdx(i)}
                onClick={() => { a.run(); onClose() }}
                style={a.danger ? { color: '#f87171' } : undefined}
              >
                <Icon size={15} />
                <span className="text-sm font-medium">{a.label}</span>
                <span className="cmdk-item-shortcut">
                  {a.hint.split(' ').map((k, j) => (
                    <span key={j}>{j > 0 && ' '}<kbd>{k}</kbd></span>
                  ))}
                </span>
                <ArrowRight size={13} style={{ color: 'var(--text-4)' }} />
              </div>
            )
          })}
        </div>
        <div className="px-4 py-2 border-t flex items-center justify-between text-[10px]"
          style={{ borderColor: 'var(--border)', color: 'var(--text-4)' }}>
          <span><kbd>↑↓</kbd> navigate · <kbd>↵</kbd> select</span>
          <span>NOCTRA AI · Command Center</span>
        </div>
      </div>
    </div>
  )
}
