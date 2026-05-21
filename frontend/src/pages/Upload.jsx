import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  Upload as UploadIcon, Play, FileText, CheckCircle2, Loader2,
  Cpu, ShieldCheck, Activity, Database, ArrowRight, ArrowLeft,
  Globe, Crosshair, Lock, Zap, FileJson, FileCode2, Server,
  HardDrive, AlertOctagon, Layers, ClipboardPaste, Trash2,
  X, FileSearch, Sparkles, GaugeCircle, Eye, ShieldAlert,
  LayoutDashboard, RefreshCw,
} from 'lucide-react'
import { ingestFile, ingestDemo } from '../api/client'
import { useSession } from '../App'

const ACCEPTED = '.csv,.json,.jsonl,.log,.txt,.ndjson'

const SEV_CLASS = {
  CRITICAL: 'sev-chip sev-chip-critical',
  HIGH:     'sev-chip sev-chip-high',
  MEDIUM:   'sev-chip sev-chip-medium',
  LOW:      'sev-chip sev-chip-low',
}

const FORMATS = [
  { label: 'CSV / TSV',      icon: FileText,   tag: 'Structured' },
  { label: 'JSON / JSONL',   icon: FileJson,   tag: 'API logs' },
  { label: 'Apache / Nginx', icon: Globe,      tag: 'Web access' },
  { label: 'Syslog',         icon: Server,     tag: 'Unix daemons' },
  { label: 'Windows Event',  icon: HardDrive,  tag: 'EVTX text' },
  { label: 'NDJSON',         icon: FileCode2,  tag: 'Streaming' },
]

const PIPELINE_STEPS = [
  { icon: Database,     label: 'Parse',        desc: 'Auto-detect format, normalize columns' },
  { icon: Cpu,          label: 'Enrich',       desc: 'IPs, users, hashes, MITRE annotations' },
  { icon: AlertOctagon, label: 'Detect',       desc: '25+ rules + behavioral anomaly + correlation' },
  { icon: Crosshair,    label: 'Score',        desc: 'AI confidence per alert · 0–100 TP probability' },
  { icon: ShieldCheck,  label: 'Triage',       desc: 'L1/L2 queues, drawer, verdicts, IR playbooks' },
]

const SAMPLE_DATASETS = [
  {
    id: 'multi-stage',
    title: 'Multi-stage attack scenario',
    desc: 'Brute force → lateral movement → exfiltration. The default demo.',
    icon: Crosshair, badge: 'CRITICAL',
    eventCount: '4.2k events',
  },
  {
    id: 'ransomware',
    title: 'Ransomware precursor (R023)',
    desc: 'Mass file rename + VSS shadow-copy deletion + service tampering.',
    icon: ShieldAlert, badge: 'CRITICAL',
    eventCount: '2.8k events',
  },
  {
    id: 'beacon-c2',
    title: 'C2 beaconing analysis (R021)',
    desc: 'Periodic outbound at fixed ~90s intervals to a single host.',
    icon: Activity, badge: 'HIGH',
    eventCount: '1.6k events',
  },
]

const SAMPLE_PASTE = `2026-05-18T10:00:01Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:08Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:12Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:18Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:24Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:31Z,198.51.100.42,LOGIN,SUCCESS,admin`

/* ─────────────────────────────────────────────────────────────────────────── */

function detectFormat(name, snippet) {
  const lower = (name || '').toLowerCase()
  if (lower.endsWith('.csv') || lower.endsWith('.tsv')) return 'CSV/TSV'
  if (lower.endsWith('.json'))   return 'JSON'
  if (lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) return 'JSON Lines'
  if (lower.endsWith('.log'))    return 'Syslog/Plain log'
  if (snippet) {
    const t = snippet.trim()
    if (t.startsWith('{') || t.startsWith('['))                            return 'JSON'
    if (/^\d{4}-\d{2}-\d{2}T/.test(t) || /^\d{1,3}\.\d{1,3}\.\d{1,3}/.test(t)) return 'CSV/TSV'
    if (/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}/.test(t))                return 'Syslog'
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*HTTP\/1\./.test(t))          return 'Apache/Nginx'
    if (/EventID/.test(t.slice(0, 300)))                                   return 'Windows Event'
  }
  return 'Plain text'
}

function humanBytes(n) {
  if (!n && n !== 0) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

async function readSnippet(file, lines = 8) {
  try {
    const slice = file.slice(0, Math.min(8192, file.size))
    const text = await slice.text()
    return text.split(/\r?\n/).slice(0, lines).join('\n')
  } catch { return '' }
}

function useRecentSessions() {
  const [sessions, setSessions] = useState([])
  useEffect(() => {
    try {
      const raw = localStorage.getItem('soc_recent')
      if (raw) setSessions(JSON.parse(raw).slice(0, 5))
    } catch {}
  }, [])
  const add = (entry) => {
    setSessions(prev => {
      const next = [entry, ...prev.filter(s => s.session_id !== entry.session_id)].slice(0, 5)
      try { localStorage.setItem('soc_recent', JSON.stringify(next)) } catch {}
      return next
    })
  }
  return { sessions, add }
}

function useApiHealth() {
  const [ok, setOk] = useState(null)
  useEffect(() => {
    fetch('/api/health', { signal: AbortSignal.timeout(3000) })
      .then(r => setOk(r.ok)).catch(() => setOk(false))
  }, [])
  return ok
}

/* ─────────────────────────────────────────────────────────────────────────── */

export default function Upload() {
  const { setSession } = useSession()
  const navigate  = useNavigate()
  const inputRef  = useRef()
  const { sessions: recentSessions, add: addRecent } = useRecentSessions()
  const apiOk     = useApiHealth()

  const [mode,      setMode]      = useState('file')    // 'file' | 'paste'
  const [dragging,  setDragging]  = useState(false)
  const [globalDrag,setGlobalDrag]= useState(false)     // full-screen drag overlay
  const [uploading, setUploading] = useState(false)
  const [progress,  setProgress]  = useState(0)
  const [activeStep,setActiveStep]= useState(0)
  const [result,    setResult]    = useState(null)

  // File metadata + preview
  const [stagedFile,setStagedFile]= useState(null)
  const [snippet,   setSnippet]   = useState('')
  const detectedFormat = useMemo(
    () => stagedFile ? detectFormat(stagedFile.name, snippet) : null,
    [stagedFile, snippet],
  )

  // Paste mode
  const [pasteText, setPasteText] = useState('')
  const pasteSnippet = pasteText.split(/\r?\n/).slice(0, 8).join('\n')
  const pasteFormat  = pasteText ? detectFormat('paste.txt', pasteText) : null

  /* ────── Pipeline step animation tied loosely to progress ────── */
  useEffect(() => {
    if (!uploading) { setActiveStep(0); return }
    // Map 0..100% across the 5 stages, with a slight settle on the last one.
    if (progress < 100) {
      setActiveStep(Math.min(PIPELINE_STEPS.length - 1, Math.floor((progress / 100) * PIPELINE_STEPS.length)))
    } else {
      const id = setInterval(() => setActiveStep(s => (s + 1) % PIPELINE_STEPS.length), 600)
      return () => clearInterval(id)
    }
  }, [uploading, progress])

  /* ────── Full-screen drag overlay (window-level) ────── */
  useEffect(() => {
    let counter = 0
    const onEnter = () => { counter++; setGlobalDrag(true) }
    const onLeave = () => { counter = Math.max(0, counter - 1); if (counter === 0) setGlobalDrag(false) }
    const onDrop  = () => { counter = 0; setGlobalDrag(false) }
    window.addEventListener('dragenter', onEnter)
    window.addEventListener('dragleave', onLeave)
    window.addEventListener('drop', onDrop)
    return () => {
      window.removeEventListener('dragenter', onEnter)
      window.removeEventListener('dragleave', onLeave)
      window.removeEventListener('drop', onDrop)
    }
  }, [])

  /* ────── Stage + preview the file (does not upload) ────── */
  const stage = async (file) => {
    if (!file) return
    if (file.size > 25 * 1024 * 1024) { toast.error('File exceeds 25 MB limit'); return }
    setStagedFile(file)
    setSnippet(await readSnippet(file, 10))
    setResult(null)
  }

  const clearStaged = () => { setStagedFile(null); setSnippet(''); setProgress(0) }

  /* ────── Send the staged file to the backend ────── */
  const sendFile = async (file) => {
    if (!file) return
    setUploading(true); setProgress(0); setResult(null)
    try {
      const { data } = await ingestFile(file, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 100))
      })
      setResult(data)
      setSession(data)
      addRecent({ session_id: data.session_id, ts: new Date().toISOString(), alert_count: data.alerts.length, event_count: data.event_count, parsed_format: data.parsed_format, filename: file.name })
      toast.success(`${data.alerts.length} alert(s) detected — choose a destination below`)
    } catch (err) {
      toast.error(err.response?.data?.detail || err.message || 'Upload failed')
    } finally { setUploading(false) }
  }

  const sendPaste = async () => {
    if (!pasteText.trim()) { toast.error('Paste something first'); return }
    const blob = new Blob([pasteText], { type: 'text/csv' })
    const file = new File([blob], 'pasted.csv', { type: 'text/csv' })
    await sendFile(file)
  }

  const loadDemoLog = async () => {
    if (uploading) return
    setUploading(true); setProgress(0); setResult(null)
    const interval = setInterval(() => { setProgress(p => (p >= 90 ? 90 : p + 20)) }, 180)
    try {
      const { data } = await ingestDemo()
      clearInterval(interval); setProgress(100)
      setResult(data)
      setSession(data)
      addRecent({ session_id: data.session_id, ts: new Date().toISOString(), alert_count: data.alerts.length, event_count: data.event_count, parsed_format: data.parsed_format, filename: 'demo-attack-scenario.csv' })
      toast.success(`${data.alerts.length} alert(s) detected — choose a destination below`)
    } catch (err) {
      clearInterval(interval)
      toast.error(err.response?.data?.detail || 'Demo session failed — is the backend running?')
    } finally { setUploading(false) }
  }

  const onFileInput = (file) => stage(file)
  const onDrop = (e) => { e.preventDefault(); setDragging(false); stage(e.dataTransfer.files[0]) }

  const sevCounts = result
    ? result.alerts.reduce((acc, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc }, {})
    : {}
  const firstAlertId = result?.alerts?.[0]?.alert_id

  return (
    <div className="max-w-5xl mx-auto py-4 space-y-7 fade-in">

      {/* Global drag overlay */}
      {globalDrag && !uploading && (
        <div className="fixed inset-0 z-[150] pointer-events-none flex items-center justify-center"
          style={{ background: 'rgba(225,29,72,0.08)', backdropFilter: 'blur(4px)' }}>
          <div className="rounded-3xl px-8 py-6 text-center"
            style={{ background: 'var(--surface)', border: '2px dashed var(--accent)', boxShadow: '0 0 60px rgba(225,29,72,.4)' }}>
            <UploadIcon size={42} color="#f43f5e" className="mx-auto mb-2" />
            <p className="text-lg font-bold text-white">Drop your log file anywhere</p>
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>CSV, JSON, syslog, Apache… up to 25 MB</p>
          </div>
        </div>
      )}

      {/* Module header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <button onClick={() => navigate('/')} className="inline-flex items-center gap-1.5 text-xs mb-2 transition-colors" style={{ color: 'var(--text-3)' }}>
            <ArrowLeft size={11} /> Back to Overview
          </button>
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl flex items-center justify-center icon-3d-red">
              <UploadIcon size={20} color="#f43f5e" strokeWidth={1.8} />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold text-white leading-tight">Ingestion Module</h1>
              <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                Drop a log file → detection engine runs → AI scores every alert → forwarded to Triage Queue
              </p>
            </div>
          </div>
        </div>
        <div className="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-full border h-fit"
          style={{
            background: apiOk ? 'rgba(34,197,94,.06)' : 'rgba(225,29,72,0.1)',
            borderColor: apiOk ? 'rgba(34,197,94,.30)' : 'rgba(225,29,72,0.4)',
            color: apiOk ? '#4ade80' : '#e11d48',
          }}>
          {apiOk ? <Activity size={11} /> : <Cpu size={11} />}
          <span className="font-semibold">
            {apiOk === null ? 'Connecting…' : apiOk ? 'Engine ready' : 'Engine offline'}
          </span>
          {apiOk && <span className="dot-live ml-1" />}
        </div>
      </div>

      {/* Mode toggle */}
      <div className="segmented w-fit">
        <button aria-selected={mode === 'file'} onClick={() => setMode('file')}>
          <UploadIcon size={12} /> File upload
        </button>
        <button aria-selected={mode === 'paste'} onClick={() => setMode('paste')}>
          <ClipboardPaste size={12} /> Paste text
        </button>
      </div>

      {/* ── FILE MODE ─────────────────────────────────────────── */}
      {mode === 'file' && !stagedFile && !uploading && !result && (
        <div
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`relative border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all duration-300 dropzone-beam ${dragging ? 'dropzone-active' : ''}`}
          style={{
            borderColor: dragging ? 'var(--accent)' : 'var(--border-2)',
            background: dragging ? 'rgba(225,29,72,0.05)' : 'rgba(255,255,255,0.015)',
            transform: dragging ? 'scale(1.01)' : 'scale(1)',
          }}
        >
          <input ref={inputRef} type="file" accept={ACCEPTED} className="hidden" onChange={e => onFileInput(e.target.files[0])} />
          <div className="space-y-5">
            <div className="w-20 h-20 rounded-3xl flex items-center justify-center mx-auto icon-float"
              style={{
                background: 'linear-gradient(145deg, #1f0d12, #2d1520)',
                boxShadow: '0 12px 40px rgba(225,29,72,0.25), 0 4px 12px rgba(0,0,0,0.5)',
                border: '1px solid rgba(225,29,72,0.25)',
              }}>
              <UploadIcon size={32} color="#f43f5e" strokeWidth={1.5} />
            </div>
            <div>
              <p className="text-xl font-bold text-white">Drop your log file here</p>
              <p className="text-sm mt-1.5" style={{ color: 'var(--text-3)' }}>
                or <span style={{ color: 'var(--accent)' }}>click to browse</span>
              </p>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-4)' }}>CSV · JSON/JSONL · Apache · Nginx · Syslog · Windows Event · up to 25 MB</p>
            <div className="pt-4 flex justify-center gap-2 flex-wrap">
              <button
                onClick={(e) => { e.stopPropagation(); loadDemoLog() }}
                className="btn-accent px-5 py-2 text-sm rounded-full inline-flex items-center gap-2 hover-glow"
              >
                <Play size={14} fill="currentColor" /> Run Demo Attack Scenario
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── FILE STAGED — preview + send ──────────────────────── */}
      {mode === 'file' && stagedFile && !uploading && !result && (
        <div className="rounded-2xl p-5 gradient-border slide-up" style={{ background: 'var(--surface)' }}>
          <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-xl flex items-center justify-center icon-3d-red">
                <FileSearch size={20} color="#f43f5e" strokeWidth={1.6} />
              </div>
              <div>
                <p className="font-bold text-white">{stagedFile.name}</p>
                <p className="text-xs num" style={{ color: 'var(--text-3)' }}>
                  {humanBytes(stagedFile.size)} · detected format <span style={{ color: 'var(--accent)' }}>{detectedFormat}</span>
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={clearStaged}
                className="text-xs px-3 py-1.5 rounded-lg border inline-flex items-center gap-1.5"
                style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
                <Trash2 size={12} /> Remove
              </button>
              <button onClick={() => sendFile(stagedFile)}
                className="btn-accent text-xs px-4 py-1.5 rounded-lg inline-flex items-center gap-1.5 hover-glow font-bold">
                <Sparkles size={12} /> Analyse
                <ArrowRight size={12} />
              </button>
            </div>
          </div>

          <p className="eyebrow mb-2">Preview · first 10 lines</p>
          <pre className="font-mono text-[11px] p-3 rounded-xl overflow-x-auto whitespace-pre"
            style={{ background: 'var(--bg)', border: '1px solid var(--border-2)', color: 'var(--text-2)', maxHeight: 200 }}>
            {snippet || '(empty)'}
          </pre>
        </div>
      )}

      {/* ── PASTE MODE ────────────────────────────────────────── */}
      {mode === 'paste' && !uploading && !result && (
        <div className="rounded-2xl p-5 gradient-border" style={{ background: 'var(--surface)' }}>
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <p className="eyebrow">Paste log content</p>
            <div className="flex items-center gap-2">
              <button onClick={() => setPasteText(SAMPLE_PASTE)}
                className="text-xs px-3 py-1.5 rounded-lg border inline-flex items-center gap-1.5"
                style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
                <FileText size={11} /> Insert sample
              </button>
              {pasteText && (
                <button onClick={() => setPasteText('')}
                  className="text-xs px-3 py-1.5 rounded-lg border inline-flex items-center gap-1.5"
                  style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
                  <X size={11} /> Clear
                </button>
              )}
            </div>
          </div>
          <textarea
            value={pasteText}
            onChange={e => setPasteText(e.target.value)}
            placeholder="Paste a CSV, JSON, Apache, or syslog snippet here…"
            rows={9}
            className="w-full font-mono text-[12px] p-3 rounded-xl resize-y outline-none"
            style={{ background: 'var(--bg)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
          />
          <div className="mt-3 flex items-center justify-between gap-2 flex-wrap">
            <p className="text-xs num" style={{ color: 'var(--text-3)' }}>
              {pasteText.length.toLocaleString()} chars
              {pasteFormat && <> · detected format <span style={{ color: 'var(--accent)' }}>{pasteFormat}</span></>}
            </p>
            <button onClick={sendPaste} disabled={!pasteText.trim()}
              className="btn-accent text-sm px-4 py-2 rounded-lg inline-flex items-center gap-1.5 hover-glow font-bold disabled:opacity-50">
              <Sparkles size={13} /> Analyse paste
              <ArrowRight size={12} />
            </button>
          </div>
        </div>
      )}

      {/* ── UPLOADING ─────────────────────────────────────────── */}
      {uploading && (
        <div className="rounded-2xl p-8 gradient-border text-center" style={{ background: 'var(--surface)' }}>
          <Loader2 size={56} className="animate-spin mx-auto" color="#f43f5e" strokeWidth={1.5} />
          <p className="font-bold text-white mt-4">Running pipeline…</p>
          <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>{PIPELINE_STEPS[activeStep].label} · {PIPELINE_STEPS[activeStep].desc}</p>
          <div className="max-w-sm mx-auto mt-5">
            <div className="flex justify-between text-xs mb-1.5 num" style={{ color: 'var(--text-3)' }}>
              <span>Processing</span>
              <span style={{ color: 'var(--accent)' }}>{progress}%</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
              <div className="h-full rounded-full progress-animated transition-all duration-300"
                style={{ width: `${progress}%`, background: 'linear-gradient(90deg, #9f1239, #e11d48, #f43f5e)' }} />
            </div>
          </div>
        </div>
      )}

      {/* ── PARSE RESULT — success ribbon + destination picker ── */}
      {result && (
        <div className="rounded-2xl p-6 slide-up gradient-border" style={{ background: 'var(--surface)' }}>
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle2 size={20} color="#4ade80" />
            <p className="font-bold text-white">Parse complete — where do you want to go next?</p>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            {[
              { label: 'Format',  value: result.parsed_format, icon: Database },
              { label: 'Events',  value: result.event_count.toLocaleString(), icon: Activity },
              { label: 'Alerts',  value: result.alerts.length, icon: AlertOctagon },
              { label: 'Session', value: result.session_id.slice(0, 8) + '…', mono: true, icon: ShieldCheck },
            ].map(({ label, value, mono, icon: I }) => (
              <div key={label} className="rounded-xl px-3 py-2.5" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-0.5">
                  <p className="text-xs" style={{ color: 'var(--text-3)' }}>{label}</p>
                  <I size={11} style={{ color: 'var(--text-4)' }} />
                </div>
                <p className={`text-white font-semibold text-sm num ${mono ? 'font-mono' : ''}`}>{value}</p>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap gap-2 mb-5">
            {Object.entries(sevCounts).map(([sev, n]) => (
              <span key={sev} className={SEV_CLASS[sev]}>{n} {sev}</span>
            ))}
            {result.alerts.length === 0 && <span className="text-sm text-emerald-400">No alerts fired — logs appear clean.</span>}
          </div>

          {/* Destination picker */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <button onClick={() => navigate('/triage')}
              className="rounded-xl p-3 text-left tile-lift transition-all"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Triage Queue</span>
                <ShieldAlert size={14} color="#f87171" />
              </div>
              <p className="text-sm font-semibold text-white">Start triaging alerts</p>
              <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>Recommended first stop</p>
            </button>
            <button onClick={() => navigate('/dashboard')}
              className="rounded-xl p-3 text-left tile-lift transition-all"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Dashboard</span>
                <LayoutDashboard size={14} color="#f87171" />
              </div>
              <p className="text-sm font-semibold text-white">See the operations view</p>
              <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>L1/L2 lens + KPIs</p>
            </button>
            <button onClick={() => firstAlertId ? navigate(`/investigate/${firstAlertId}`) : navigate('/triage')}
              className="rounded-xl p-3 text-left tile-lift transition-all"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}
              disabled={!firstAlertId}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Investigate</span>
                <Eye size={14} color="#f87171" />
              </div>
              <p className="text-sm font-semibold text-white">Open first incident</p>
              <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>Forensic deep-dive</p>
            </button>
          </div>

          <div className="mt-4 flex items-center gap-2 flex-wrap">
            <button onClick={() => { setResult(null); clearStaged(); setPasteText('') }}
              className="text-xs px-3 py-1.5 rounded-lg border inline-flex items-center gap-1.5"
              style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
              <RefreshCw size={11} /> Ingest another file
            </button>
          </div>
        </div>
      )}

      {/* ── SAMPLE GALLERY ────────────────────────────────────── */}
      {!uploading && !result && (
        <div>
          <p className="eyebrow mb-3">Sample attack datasets</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {SAMPLE_DATASETS.map(s => {
              const I = s.icon
              return (
                <button key={s.id} onClick={loadDemoLog}
                  className="rounded-2xl p-4 text-left tile-lift transition-all"
                  style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center icon-3d-red">
                      <I size={16} color="#f43f5e" />
                    </div>
                    <span className={SEV_CLASS[s.badge]}>{s.badge}</span>
                  </div>
                  <p className="text-sm font-bold text-white">{s.title}</p>
                  <p className="text-xs mt-1 leading-snug" style={{ color: 'var(--text-3)' }}>{s.desc}</p>
                  <p className="text-[10px] mt-2 num inline-flex items-center gap-1.5" style={{ color: 'var(--text-4)' }}>
                    <GaugeCircle size={10} /> {s.eventCount}
                  </p>
                </button>
              )
            })}
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-4)' }}>
            Each sample spins up a real backend session against the bundled multi-stage scenario — adjust the live demo to your investigation lens.
          </p>
        </div>
      )}

      {/* ── PIPELINE DIAGRAM ──────────────────────────────────── */}
      <div className="rounded-2xl p-5 gradient-border" style={{ background: 'var(--surface)' }}>
        <p className="eyebrow mb-4">Detection pipeline</p>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {PIPELINE_STEPS.map((s, i) => {
            const I = s.icon
            const live = uploading && i === activeStep
            return (
              <div key={s.label} className="rounded-xl p-3 transition-all"
                style={{
                  background: live ? 'rgba(225,29,72,.08)' : 'var(--surface-2)',
                  border: `1px solid ${live ? 'rgba(225,29,72,.4)' : 'var(--border)'}`,
                  boxShadow: live ? '0 0 18px rgba(225,29,72,.25)' : 'none',
                }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest num" style={{ color: 'var(--text-4)' }}>0{i + 1}</span>
                  <I size={14} color={live ? '#f87171' : '#9ca3af'} />
                </div>
                <p className="text-sm font-bold text-white">{s.label}</p>
                <p className="text-[10px] leading-tight mt-1" style={{ color: 'var(--text-3)' }}>{s.desc}</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── RECENT SESSIONS ───────────────────────────────────── */}
      {recentSessions.length > 0 && (
        <div>
          <p className="eyebrow mb-3">Recent Sessions</p>
          <div className="space-y-2">
            {recentSessions.map(s => (
              <div key={s.session_id}
                className="flex items-center gap-3 px-4 py-3 rounded-xl text-xs tile-lift cursor-pointer"
                style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
                <FileText size={13} style={{ color: 'var(--text-3)' }} />
                <span className="font-mono shrink-0 num" style={{ color: 'var(--text-3)' }}>{s.session_id.slice(0, 8)}</span>
                <span className="flex-1 truncate" style={{ color: 'var(--text-2)' }}>{s.filename || 'Unknown file'}</span>
                <span style={{ color: 'var(--text-3)' }} className="hidden sm:block num">{s.alert_count} alerts</span>
                <span style={{ color: 'var(--text-4)' }} className="num">{new Date(s.ts).toLocaleDateString()}</span>
                <ArrowRight size={12} style={{ color: 'var(--text-4)' }} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── FORMAT GRID ───────────────────────────────────────── */}
      <div>
        <p className="eyebrow mb-3">Supported Log Formats</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {FORMATS.map(({ label, icon: I, tag }) => (
            <div key={label}
              className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-sm font-medium transition-all tile-lift"
              style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
              <I size={14} style={{ color: 'var(--accent)' }} />
              <div className="flex-1 min-w-0">
                <p className="text-white truncate">{label}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>{tag}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── PRIVACY FOOTER ────────────────────────────────────── */}
      <div className="rounded-xl px-4 py-3 flex items-center gap-3 text-xs" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
        <Lock size={13} color="#4ade80" />
        <span style={{ color: 'var(--text-2)' }}>
          <span className="text-white font-semibold">Zero-persistence:</span> files are parsed in memory and discarded the moment you clear the session. Nothing is written to disk, database, or third-party.
        </span>
      </div>
    </div>
  )
}
