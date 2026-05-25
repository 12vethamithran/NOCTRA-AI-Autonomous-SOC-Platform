/**
 * Upload — Ingestion Module.
 *
 * Enterprise rewrite (v3.2): the playful gradient hero is replaced with a
 * tight workflow surface. Every flow from v3.1 is preserved:
 *   file mode · paste mode · staged preview · upload progress · result
 *   destinations · sample datasets · recent sessions · format reference ·
 *   global drag overlay · engine health · run-demo path.
 *
 * Visual layer is now built on Card / SectionHeader / StatusPill so it
 * matches the redesigned Landing page and reads as one product.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import {
  Upload as UploadIcon, Play, FileText, CheckCircle2, Loader2,
  Cpu, ShieldCheck, Activity, Database, ArrowRight, ArrowLeft,
  Globe, Crosshair, Lock, FileJson, FileCode2, Server,
  HardDrive, AlertOctagon, Layers, ClipboardPaste, Trash2,
  X, FileSearch, Sparkles, Eye, ShieldAlert,
  LayoutDashboard, RefreshCw, GitBranch, FileBarChart,
} from 'lucide-react'
import { ingestFile, ingestDemo } from '../api/client'
import { useSession } from '../App'
import useApiHealth from '../utils/useApiHealth'
import Card from '../components/ui/Card'
import SectionHeader from '../components/ui/SectionHeader'
import StatusPill from '../components/ui/StatusPill'
import SeverityBadge from '../components/ui/SeverityBadge'

const ACCEPTED = '.csv,.tsv,.json,.jsonl,.ndjson,.log,.txt,.out,.syslog,.evt'

const FORMATS = [
  { label: 'CSV / TSV',      icon: FileText,   tag: 'Auto-delimiter' },
  { label: 'JSON / JSONL',   icon: FileJson,   tag: 'API logs' },
  { label: 'Apache / Nginx', icon: Globe,      tag: 'Web access' },
  { label: 'Syslog',         icon: Server,     tag: 'Unix daemons' },
  { label: 'Windows Event',  icon: HardDrive,  tag: 'EVTX text' },
  { label: 'logfmt / KV',    icon: FileCode2,  tag: 'key=value' },
  { label: 'NDJSON',         icon: FileCode2,  tag: 'Streaming' },
  { label: 'Anything else',  icon: Layers,     tag: 'Generic fallback' },
]

// 9 stages — matches the backend pipeline after the dedup pass.
const PIPELINE_STEPS = [
  { icon: Database,     label: 'Ingest',    desc: 'Auto-detect format, parse rows' },
  { icon: Cpu,          label: 'Normalize', desc: 'Collapse 40+ aliases to canonical fields' },
  { icon: AlertOctagon, label: 'Detect',    desc: '42 rules + UEBA anomaly + correlation' },
  { icon: Sparkles,     label: 'Score',     desc: 'AI TP probability + SHAP attribution' },
  { icon: Globe,        label: 'Enrich',    desc: 'IP rep, geo, ASN, hash → MITRE' },
  { icon: GitBranch,    label: 'Chain',     desc: 'Stitch alerts into kill chains' },
  { icon: Layers,       label: 'Dedup',     desc: 'Collapse identical alerts' },
  { icon: Eye,          label: 'Triage',    desc: 'Hand off to L1/L2 queues' },
  { icon: FileBarChart, label: 'Report',    desc: 'Forensic PDF on demand' },
]

const SAMPLE_DATASETS = [
  { id: 'multi-stage', title: 'Multi-stage kill chain',  desc: 'Brute force → lateral movement → exfiltration.',          icon: Crosshair,   badge: 'CRITICAL', eventCount: '4.2k events' },
  { id: 'ransomware',  title: 'Ransomware precursor',    desc: 'Mass file rename + VSS shadow delete + svc tampering.',   icon: ShieldAlert, badge: 'CRITICAL', eventCount: '2.8k events' },
  { id: 'beacon-c2',   title: 'C2 beacon analysis',      desc: 'Periodic outbound at ~90s intervals to one host.',        icon: Activity,    badge: 'HIGH',     eventCount: '1.6k events' },
]

const SAMPLE_PASTE = `2026-05-18T10:00:01Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:08Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:12Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:18Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:24Z,198.51.100.42,LOGIN,FAILED,admin
2026-05-18T10:00:31Z,198.51.100.42,LOGIN,SUCCESS,admin`

/* ── HELPERS ──────────────────────────────────────────────────────────────── */

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

const HEALTH_PILL = {
  online:   { tone: 'success', label: 'Engine online',   icon: Activity, dot: true,  pulse: true },
  degraded: { tone: 'warning', label: 'Engine degraded', icon: Activity, dot: true,  pulse: false },
  offline:  { tone: 'danger',  label: 'Engine offline',  icon: Cpu,      dot: true,  pulse: false },
  checking: { tone: 'neutral', label: 'Connecting…',     icon: Cpu,      dot: false, pulse: false },
}

/* ── PAGE ─────────────────────────────────────────────────────────────────── */

export default function Upload() {
  const { setSession } = useSession()
  const navigate    = useNavigate()
  const inputRef    = useRef()
  const { sessions: recentSessions, add: addRecent } = useRecentSessions()
  const health      = useApiHealth()
  const healthMeta  = HEALTH_PILL[health] || HEALTH_PILL.checking

  const [mode,       setMode]       = useState('file')   // 'file' | 'paste'
  const [dragging,   setDragging]   = useState(false)
  const [globalDrag, setGlobalDrag] = useState(false)
  const [uploading,  setUploading]  = useState(false)
  const [progress,   setProgress]   = useState(0)
  const [activeStep, setActiveStep] = useState(0)
  const [result,     setResult]     = useState(null)

  const [stagedFile, setStagedFile] = useState(null)
  const [snippet,    setSnippet]    = useState('')
  const detectedFormat = useMemo(
    () => (stagedFile ? detectFormat(stagedFile.name, snippet) : null),
    [stagedFile, snippet],
  )

  const [pasteText, setPasteText] = useState('')
  const pasteFormat = pasteText ? detectFormat('paste.txt', pasteText) : null

  // Map upload progress to the 9 pipeline stages.
  useEffect(() => {
    if (!uploading) { setActiveStep(0); return }
    if (progress < 100) {
      setActiveStep(Math.min(PIPELINE_STEPS.length - 1, Math.floor((progress / 100) * PIPELINE_STEPS.length)))
    } else {
      const id = setInterval(() => setActiveStep(s => (s + 1) % PIPELINE_STEPS.length), 500)
      return () => clearInterval(id)
    }
  }, [uploading, progress])

  // Global drag-and-drop overlay.
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

  const stage = async (file) => {
    if (!file) return
    if (file.size > 25 * 1024 * 1024) { toast.error('File exceeds 25 MB limit'); return }
    setStagedFile(file)
    setSnippet(await readSnippet(file, 10))
    setResult(null)
  }

  const clearStaged = () => { setStagedFile(null); setSnippet(''); setProgress(0) }

  const sendFile = async (file) => {
    if (!file) return
    setUploading(true); setProgress(0); setResult(null)
    try {
      const { data } = await ingestFile(file, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 100))
      })
      setResult(data)
      setSession(data)
      addRecent({
        session_id: data.session_id, ts: new Date().toISOString(),
        alert_count: data.alerts.length, event_count: data.event_count,
        parsed_format: data.parsed_format, filename: file.name,
      })
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
      addRecent({
        session_id: data.session_id, ts: new Date().toISOString(),
        alert_count: data.alerts.length, event_count: data.event_count,
        parsed_format: data.parsed_format, filename: 'demo-attack-scenario.csv',
      })
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
    <div className="max-w-6xl mx-auto px-5 lg:px-8 py-6 space-y-6 fade-in">

      {/* Global drag overlay */}
      {globalDrag && !uploading && (
        <div className="fixed inset-0 z-[150] pointer-events-none flex items-center justify-center"
          style={{ background: 'rgba(225,29,72,0.06)', backdropFilter: 'blur(6px)' }}>
          <Card variant="elevated" padding="lg" className="text-center pointer-events-none"
            style={{ borderStyle: 'dashed', borderColor: 'var(--accent)' }}>
            <UploadIcon size={36} color="var(--accent)" className="mx-auto mb-3" />
            <p className="font-semibold" style={{ color: 'var(--text-1)' }}>Drop your log file anywhere</p>
            <p className="text-sm mt-1" style={{ color: 'var(--text-3)' }}>CSV · JSON · syslog · Apache · up to 25 MB</p>
          </Card>
        </div>
      )}

      {/* Header */}
      <SectionHeader
        variant="display-sm"
        eyebrow="INGESTION MODULE"
        title="DROP A LOG. RANK THE INCIDENTS."
        hint="Parsed in memory, scored against 42 rules, deduplicated, then handed to the triage queue. The session lives only in RAM."
        right={
          <div className="flex items-center gap-2">
            <button onClick={() => navigate('/')}
              className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md transition-colors"
              style={{ color: 'var(--text-3)', background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}>
              <ArrowLeft size={11} /> Overview
            </button>
            <StatusPill
              tone={healthMeta.tone}
              dot={healthMeta.dot}
              pulse={healthMeta.pulse}
              icon={healthMeta.icon}
            >
              {healthMeta.label}
            </StatusPill>
          </div>
        }
      />

      {/* Two-column layout: input on the left, context on the right. */}
      <div className="grid lg:grid-cols-[1.7fr_1fr] gap-5 items-start">

        <div className="space-y-5 min-w-0">

          {/* Mode toggle */}
          <div className="segmented w-fit">
            <button aria-selected={mode === 'file'}  onClick={() => setMode('file')}><UploadIcon size={12} /> File upload</button>
            <button aria-selected={mode === 'paste'} onClick={() => setMode('paste')}><ClipboardPaste size={12} /> Paste text</button>
          </div>

          {/* FILE MODE — empty dropzone */}
          {mode === 'file' && !stagedFile && !uploading && !result && (
            <Card variant="elevated" padding="none">
              <div
                onClick={() => inputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                role="button"
                tabIndex={0}
                aria-label="Drop log file or click to browse"
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click() }}
                className="rounded-[14px] cursor-pointer transition-colors"
                style={{
                  padding: '56px 24px',
                  textAlign: 'center',
                  border: `1.5px dashed ${dragging ? 'var(--accent)' : 'var(--border-3)'}`,
                  background: dragging ? 'rgba(225,29,72,0.04)' : 'transparent',
                  borderRadius: 14,
                }}
              >
                <input ref={inputRef} type="file" accept={ACCEPTED} className="hidden"
                  onChange={e => onFileInput(e.target.files[0])} />
                <div className="w-12 h-12 mx-auto rounded-lg flex items-center justify-center mb-4"
                  style={{ background: 'var(--surface-3)', color: 'var(--accent)' }}>
                  <UploadIcon size={20} />
                </div>
                <p className="font-semibold" style={{ color: 'var(--text-1)' }}>
                  Drop a log file or <span style={{ color: 'var(--accent)' }}>browse</span>
                </p>
                <p className="text-xs mt-1.5" style={{ color: 'var(--text-3)' }}>
                  CSV · JSON / JSONL · Apache · syslog · Windows Event · logfmt · any text log · up to 25 MB
                </p>
                <div className="mt-5">
                  <button onClick={(e) => { e.stopPropagation(); loadDemoLog() }}
                    className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md font-semibold transition-colors"
                    style={{ background: 'var(--accent)', color: '#fff' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent)')}
                  >
                    <Play size={11} fill="currentColor" /> Run demo attack scenario
                  </button>
                </div>
              </div>
            </Card>
          )}

          {/* FILE MODE — staged */}
          {mode === 'file' && stagedFile && !uploading && !result && (
            <Card variant="elevated" padding="lg" className="slide-up">
              <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
                    <FileSearch size={18} />
                  </div>
                  <div className="min-w-0">
                    <p className="font-semibold truncate" style={{ color: 'var(--text-1)' }}>{stagedFile.name}</p>
                    <p className="text-xs tabular" style={{ color: 'var(--text-3)' }}>
                      {humanBytes(stagedFile.size)} · detected format <span style={{ color: 'var(--accent)' }}>{detectedFormat}</span>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button onClick={clearStaged}
                    className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                    <Trash2 size={11} /> Remove
                  </button>
                  <button onClick={() => sendFile(stagedFile)}
                    className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md font-semibold transition-colors"
                    style={{ background: 'var(--accent)', color: '#fff' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent)')}
                  >
                    <Sparkles size={11} /> Analyse <ArrowRight size={11} />
                  </button>
                </div>
              </div>
              <p className="ent-section-eyebrow mb-2">Preview · first 10 lines</p>
              <pre className="font-mono text-[11.5px] p-3 rounded-md overflow-auto whitespace-pre tabular w-full max-w-full"
                style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text-2)', maxHeight: 240 }}>
                {snippet || '(empty)'}
              </pre>
            </Card>
          )}

          {/* PASTE MODE */}
          {mode === 'paste' && !uploading && !result && (
            <Card variant="elevated" padding="lg">
              <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                <p className="ent-section-eyebrow">Paste log content</p>
                <div className="flex items-center gap-2">
                  <button onClick={() => setPasteText(SAMPLE_PASTE)}
                    className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                    <FileText size={11} /> Insert sample
                  </button>
                  {pasteText && (
                    <button onClick={() => setPasteText('')}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md"
                      style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                      <X size={11} /> Clear
                    </button>
                  )}
                </div>
              </div>
              <textarea
                value={pasteText}
                onChange={e => setPasteText(e.target.value)}
                placeholder="Paste a CSV, JSON, Apache, or syslog snippet here…"
                rows={10}
                className="w-full font-mono text-[12px] p-3 rounded-md resize-y outline-none tabular"
                style={{ background: 'var(--bg)', border: '1px solid var(--border-2)', color: 'var(--text-1)' }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent)')}
                onBlur={e => (e.target.style.borderColor = 'var(--border-2)')}
              />
              <div className="mt-3 flex items-center justify-between gap-2 flex-wrap">
                <p className="text-xs tabular" style={{ color: 'var(--text-3)' }}>
                  {pasteText.length.toLocaleString()} chars
                  {pasteFormat && <> · detected format <span style={{ color: 'var(--accent)' }}>{pasteFormat}</span></>}
                </p>
                <button onClick={sendPaste} disabled={!pasteText.trim()}
                  className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md font-semibold transition-colors disabled:opacity-50"
                  style={{ background: 'var(--accent)', color: '#fff' }}
                  onMouseEnter={e => !e.currentTarget.disabled && (e.currentTarget.style.background = 'var(--accent-hover)')}
                  onMouseLeave={e => !e.currentTarget.disabled && (e.currentTarget.style.background = 'var(--accent)')}
                >
                  <Sparkles size={11} /> Analyse paste <ArrowRight size={11} />
                </button>
              </div>
            </Card>
          )}

          {/* UPLOADING */}
          {uploading && (
            <Card variant="elevated" padding="lg" className="text-center">
              <Loader2 size={36} className="animate-spin mx-auto" color="var(--accent)" strokeWidth={1.5} />
              <p className="font-semibold mt-4" style={{ color: 'var(--text-1)' }}>Running pipeline…</p>
              <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>
                {PIPELINE_STEPS[activeStep].label} · {PIPELINE_STEPS[activeStep].desc}
              </p>
              <div className="max-w-md mx-auto mt-5">
                <div className="flex justify-between text-xs mb-1.5 tabular" style={{ color: 'var(--text-3)' }}>
                  <span>Processing</span>
                  <span style={{ color: 'var(--accent)' }}>{progress}%</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
                  <div className="h-full rounded-full progress-animated transition-all duration-300"
                    style={{ width: `${progress}%`, background: 'var(--accent)' }} />
                </div>
              </div>
            </Card>
          )}

          {/* RESULT */}
          {result && (
            <Card variant="elevated" padding="lg" className="slide-up">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle2 size={18} color="var(--success)" />
                <p className="font-semibold" style={{ color: 'var(--text-1)' }}>
                  Parse complete — choose a destination
                </p>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
                {[
                  { label: 'Format',  value: result.parsed_format, icon: Database },
                  { label: 'Events',  value: result.event_count.toLocaleString(), icon: Activity },
                  { label: 'Alerts',  value: result.alerts.length, icon: AlertOctagon },
                  { label: 'Session', value: result.session_id.slice(0, 8) + '…', mono: true, icon: ShieldCheck },
                ].map(({ label, value, mono, icon: I }) => (
                  <div key={label} className="rounded-md px-3 py-2.5"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <div className="flex items-center justify-between mb-0.5">
                      <p className="ent-section-eyebrow">{label}</p>
                      <I size={11} style={{ color: 'var(--text-4)' }} />
                    </div>
                    <p className={`font-semibold text-sm tabular ${mono ? 'font-mono' : ''}`}
                      style={{ color: 'var(--text-1)' }}>{value}</p>
                  </div>
                ))}
              </div>

              <div className="flex flex-wrap gap-2 mb-5">
                {Object.entries(sevCounts).map(([sev, n]) => (
                  <SeverityBadge key={sev} sev={sev} label={`${n} ${sev}`} />
                ))}
                {result.alerts.length === 0 && (
                  <StatusPill tone="success">No alerts fired — logs appear clean</StatusPill>
                )}
              </div>

              {/* Destination picker */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {[
                  { to: '/triage', title: 'Triage queue', sub: 'Recommended first stop', icon: ShieldAlert },
                  { to: '/dashboard', title: 'Dashboard', sub: 'L1/L2 KPIs', icon: LayoutDashboard },
                  { to: firstAlertId ? `/investigate/${firstAlertId}` : '/triage', title: 'Investigate', sub: 'Forensic deep-dive', icon: Eye, disabled: !firstAlertId },
                ].map(({ to, title, sub, icon: I, disabled }) => (
                  <button key={title}
                    onClick={() => navigate(to)}
                    disabled={disabled}
                    className="text-left p-3 rounded-md lift ring-accent disabled:opacity-40 disabled:cursor-not-allowed"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)' }}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="ent-section-eyebrow">{title}</span>
                      <I size={13} style={{ color: 'var(--accent)' }} />
                    </div>
                    <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{title}</p>
                    <p className="text-xs" style={{ color: 'var(--text-3)' }}>{sub}</p>
                  </button>
                ))}
              </div>

              <div className="mt-4 flex items-center gap-2">
                <button onClick={() => { setResult(null); clearStaged(); setPasteText('') }}
                  className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-2)' }}>
                  <RefreshCw size={11} /> Ingest another file
                </button>
              </div>
            </Card>
          )}

          {/* Sample datasets */}
          {!uploading && !result && (
            <div className="space-y-3">
              <SectionHeader eyebrow="Sample datasets" title="Try without your own data" level={2}
                hint="Each sample runs a real backend session against the bundled multi-stage scenario." />
              <div className="grid sm:grid-cols-3 gap-2">
                {SAMPLE_DATASETS.map(s => {
                  const I = s.icon
                  return (
                    <button key={s.id} onClick={loadDemoLog}
                      className="text-left p-3 rounded-md lift ring-accent"
                      style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="w-8 h-8 rounded-md flex items-center justify-center"
                          style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
                          <I size={14} />
                        </div>
                        <SeverityBadge sev={s.badge} />
                      </div>
                      <p className="text-sm font-semibold" style={{ color: 'var(--text-1)' }}>{s.title}</p>
                      <p className="text-xs mt-1" style={{ color: 'var(--text-3)', lineHeight: 1.5 }}>{s.desc}</p>
                      <p className="text-[10.5px] mt-2 tabular" style={{ color: 'var(--text-4)' }}>{s.eventCount}</p>
                    </button>
                  )
                })}
              </div>
            </div>
          )}
        </div>

        {/* ─── RIGHT RAIL — context ─── */}
        <div className="space-y-5">

          {/* Pipeline diagram */}
          <Card variant="elevated" padding="lg">
            <p className="ent-section-eyebrow mb-3">Detection pipeline</p>
            <ol className="space-y-2.5">
              {PIPELINE_STEPS.map((s, i) => {
                const I = s.icon
                const live = uploading && i === activeStep
                return (
                  <li key={s.label} className="flex items-start gap-2.5">
                    <div className="w-6 h-6 rounded-md flex items-center justify-center shrink-0 tabular text-[10.5px] font-bold"
                      style={{
                        background: live ? 'var(--accent-dim)' : 'var(--surface-3)',
                        color: live ? 'var(--accent)' : 'var(--text-3)',
                        border: `1px solid ${live ? 'var(--accent)' : 'var(--border-2)'}`,
                      }}>
                      {String(i + 1).padStart(2, '0')}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="flex items-center gap-1.5 text-sm font-semibold"
                        style={{ color: live ? 'var(--text-1)' : 'var(--text-2)' }}>
                        <I size={12} style={{ color: live ? 'var(--accent)' : 'var(--text-4)' }} />
                        {s.label}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{s.desc}</p>
                    </div>
                  </li>
                )
              })}
            </ol>
          </Card>

          {/* Recent sessions */}
          {recentSessions.length > 0 && (
            <Card padding="lg">
              <p className="ent-section-eyebrow mb-3">Recent sessions</p>
              <div className="space-y-1.5">
                {recentSessions.map(s => (
                  <div key={s.session_id}
                    className="flex items-center gap-2.5 px-2.5 py-2 rounded-md text-xs"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                    <FileText size={12} style={{ color: 'var(--text-3)' }} />
                    <span className="font-mono shrink-0 tabular" style={{ color: 'var(--text-3)' }}>{s.session_id.slice(0, 8)}</span>
                    <span className="flex-1 truncate" style={{ color: 'var(--text-1)' }}>{s.filename || 'Unknown file'}</span>
                    <span className="hidden sm:inline tabular" style={{ color: 'var(--text-3)' }}>{s.alert_count} alerts</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Supported formats */}
          <Card padding="lg">
            <p className="ent-section-eyebrow mb-3">Supported formats</p>
            <div className="grid grid-cols-2 gap-1.5">
              {FORMATS.map(({ label, icon: I, tag }) => (
                <div key={label} className="flex items-center gap-2 px-2 py-1.5 rounded-md"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <I size={12} style={{ color: 'var(--accent)' }} />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold truncate" style={{ color: 'var(--text-1)' }}>{label}</p>
                    <p className="text-[10px]" style={{ color: 'var(--text-4)' }}>{tag}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Privacy footer */}
          <Card padding="md">
            <div className="flex items-start gap-2">
              <Lock size={13} style={{ color: 'var(--success)' }} className="mt-0.5 shrink-0" />
              <p className="text-xs" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>
                <span className="font-semibold" style={{ color: 'var(--text-1)' }}>Zero-persistence.</span>{' '}
                Files are parsed in memory and discarded the moment you clear the session.
                Nothing is written to disk, database, or third-party.
              </p>
            </div>
          </Card>

        </div>
      </div>
    </div>
  )
}
