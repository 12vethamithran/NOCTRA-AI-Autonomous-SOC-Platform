import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Sparkles, Globe, Crosshair, ClipboardList, BarChart3, Lock,
  Upload as UploadIcon, ArrowRight, Activity, Cpu, ShieldCheck,
  Database, Zap, Bot, Layers, FileBarChart, Network, ShieldAlert,
  CheckCircle2, Eye, Workflow, GitBranch, AlertOctagon, TerminalSquare,
  ChevronRight, Clock, FlaskConical, ScrollText, Search, ChevronLeft,
  Play, Pause, Filter, Pin,
} from 'lucide-react'
import { useSession } from '../App'

/* ─────────────────────────────────────────────────────────────────────────────
   DATA
   ──────────────────────────────────────────────────────────────────────────── */

const SEV_CLASS = {
  CRITICAL: 'sev-chip sev-chip-critical',
  HIGH:     'sev-chip sev-chip-high',
  MEDIUM:   'sev-chip sev-chip-medium',
  LOW:      'sev-chip sev-chip-low',
}

const HERO_STATS = [
  { v: 50,  unit: 'ms', l: 'Detection p50',   icon: Zap,         sub: 'rule eval latency', invert: true },
  { v: 25,  unit: '+',  l: 'Detection rules', icon: ShieldCheck, sub: 'built-in + custom' },
  { v: 12,  unit: '',   l: 'MITRE tactics',   icon: Crosshair,   sub: 'kill-chain coverage' },
  { v: 0,   unit: '',   l: 'Bytes stored',    icon: Lock,        sub: 'storageless by design' },
]

const TICKER_ITEMS = [
  { sev: 'CRITICAL', t: 'T1110 · Credential Brute Force from 198.51.100.42' },
  { sev: 'HIGH',     t: 'T1078 · Valid Accounts · impossible-travel · jakarta → lima' },
  { sev: 'HIGH',     t: 'T1486 · Data Encrypted for Impact · srv-fileshare-04' },
  { sev: 'MEDIUM',   t: 'T1059.001 · PowerShell encoded base64 payload' },
  { sev: 'CRITICAL', t: 'T1071.004 · DNS tunneling · periodic 90s beaconing' },
  { sev: 'HIGH',     t: 'T1003.001 · LSASS memory access · suspicious parent' },
  { sev: 'MEDIUM',   t: 'T1021.001 · Lateral RDP · 10.0.4.7 → 10.0.5.31' },
  { sev: 'CRITICAL', t: 'T1190 · SQL injection probe against /api/users' },
]

const CAPABILITY_TABS = [
  {
    key: 'triage', label: 'Triage', icon: ShieldAlert,
    title: 'AI-augmented triage queue',
    bullets: [
      'Every alert receives a 0–100 TP probability with rationale',
      'Drawer with raw evidence, MITRE context, suggested IR playbook',
      'Bulk verdicts, AI auto-apply, keyboard-driven workflow',
      'Severity sorting, MITRE filter, NL search across rules & IPs',
    ],
    blurb: 'Designed for an analyst clearing 100 alerts/hour. Keyboard-first, AI-assisted, opinionated defaults — but every decision is yours.',
  },
  {
    key: 'hunt', label: 'Threat Hunt', icon: Crosshair,
    title: 'Hypothesis-driven hunting',
    bullets: [
      'Saved templates: off-hours, large outbound, multi-host auth',
      'Custom filters compose into a typed DSL',
      'Natural-language → DSL translation by the AI agent',
      'Save matching rows back as user-generated alerts',
    ],
    blurb: 'Pivot from any IOC into a structured hunt without writing SPL or KQL. The query stays explainable; nothing happens behind the curtain.',
  },
  {
    key: 'rules', label: 'Rule Builder', icon: ClipboardList,
    title: 'Custom detection rules',
    bullets: [
      'Four prebuilt templates: brute, lateral, exfil, priv-esc',
      'Multi-condition filters with AND/OR logic',
      'Severity assignment + MITRE technique mapping',
      'Live test against the current session before committing',
    ],
    blurb: 'Add your environment\'s tribal knowledge to the engine. Custom rules live alongside the 25 built-ins — same scoring, same MITRE annotation.',
  },
  {
    key: 'agent', label: 'AI Agent', icon: Bot,
    title: 'Autonomous investigation agent',
    bullets: [
      'Multi-turn conversation with full alert context',
      'Pivots into timeline / IOCs / threat intel automatically',
      'Drafts your case notes and recommended next step',
      'Falls back to deterministic heuristics when AI is unavailable',
    ],
    blurb: 'A senior-analyst sidekick that asks the next obvious question for you. Always cites which evidence it used.',
  },
]

const MITRE_TACTICS = [
  { code: 'TA0001', name: 'Initial Access',          rules: ['R022','R024','R029','R034','R041'],         color: '#e11d48' },
  { code: 'TA0002', name: 'Execution',               rules: ['R011','R032'],                              color: '#f43f5e' },
  { code: 'TA0003', name: 'Persistence',             rules: ['R007','R017','R025','R030'],                color: '#9f1239' },
  { code: 'TA0004', name: 'Privilege Escalation',    rules: ['R003'],                                     color: '#ff4d4d' },
  { code: 'TA0005', name: 'Defense Evasion',         rules: ['R012','R018','R019','R031','R035','R036','R037','R038'], color: '#be123c' },
  { code: 'TA0006', name: 'Credential Access',       rules: ['R001','R010','R013','R015','R016','R033'],  color: '#e11d48' },
  { code: 'TA0007', name: 'Discovery',               rules: ['R002','R042'],                              color: '#881337' },
  { code: 'TA0008', name: 'Lateral Movement',        rules: ['R004','R020'],                              color: '#f43f5e' },
  { code: 'TA0009', name: 'Collection',              rules: ['R039','R040'],                              color: '#9f1239' },
  { code: 'TA0011', name: 'Command & Control',       rules: ['R014','R021','R026','R028'],                color: '#e11d48' },
  { code: 'TA0010', name: 'Exfiltration',            rules: ['R005','R027'],                              color: '#be123c' },
  { code: 'TA0040', name: 'Impact',                  rules: ['R023'],                                     color: '#ff4d4d' },
]

const PIPELINE = [
  { step: '01', icon: Database,     label: 'Ingest',    desc: 'Auto-detect format (CSV, JSON, syslog, EVTX, web access).' },
  { step: '02', icon: Cpu,          label: 'Normalize', desc: 'Standardize columns: ts, ip, user, action, status, port.' },
  { step: '03', icon: ShieldAlert,  label: 'Detect',    desc: '42 rules + behavioral anomaly + cross-event correlation.' },
  { step: '04', icon: Sparkles,     label: 'Score',     desc: 'AI per-alert TP probability with rationale & SHAP features.' },
  { step: '05', icon: Globe,        label: 'Enrich',    desc: 'IP reputation, geo, ASN, hash lookup, MITRE mapping.' },
  { step: '06', icon: GitBranch,    label: 'Chain',     desc: 'Correlate alerts into incident chains by shared entities.' },
  { step: '07', icon: Eye,          label: 'Triage',    desc: 'L1 queue · drawer with playbook · TP/FP verdicts.' },
  { step: '08', icon: FileBarChart, label: 'Report',    desc: 'L1 shift handover or L2 forensic dossier · PDF export.' },
]

const FAQS = [
  { q: 'Where does the AI scoring come from?',          a: 'Each alert is sent to a Gemini-backed classifier with the relevant context (rule, MITRE technique, timestamps, source IP behavior). The model returns a 0–1 TP probability plus a short rationale shown in the drawer. When Gemini is unavailable, a deterministic 10-signal heuristic scores instead and always explains itself.' },
  { q: 'Do I have to train it on my data?',             a: 'No. Rules and the AI classifier are pre-tuned. The Learning Insights tab refines per-session weighting based on your TP/FP feedback in real time, but it never persists.' },
  { q: 'What if my log format isn\'t listed?',          a: 'The ingest engine attempts heuristic column extraction even for unknown CSVs. JSON and JSONL also work out-of-the-box. For ad-hoc formats the Rule Builder lets you define custom field maps.' },
  { q: 'How is detection accuracy >90%?',               a: 'Three layers combine: (1) deterministic rules with tight thresholds and pre-set confidence floors, (2) behavioral anomaly scoring per user/host, (3) AI re-scoring against MITRE context. Cross-signal alerts converge above 90% TP probability.' },
  { q: 'Is my data sent anywhere?',                     a: 'Only the alert envelope (rule, technique, timestamps, optional anonymised IP/user) is sent to the AI classifier — never raw log lines. Files stay in memory. Clear the session and the data is gone.' },
  { q: 'Can I bring my own detection rules?',           a: 'Yes — the Rule Builder ships with four templates (brute force, lateral movement, data exfiltration, privilege escalation). You can compose multi-condition filters, assign severity, and map a MITRE technique. Custom rules run alongside built-ins.' },
  { q: 'How does the L1 vs L2 split work?',             a: 'The dashboard ships two role lenses. L1 is queue-driven and concise — built for shift work. L2 is forensic and dense — composite threat score, kill-chain reconstruction, top entities, hypothesis-driven hunts. The role switch also changes the exported report template.' },
]

const TOC = [
  { id: 'hero',         label: 'Overview' },
  { id: 'how',          label: 'How it works' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'mitre',        label: 'MITRE coverage' },
  { id: 'tiers',        label: 'L1 vs L2' },
  { id: 'engine',       label: 'Detection engine' },
  { id: 'demo',         label: 'Live demo' },
  { id: 'security',     label: 'Security' },
  { id: 'faq',          label: 'FAQ' },
]

/* ─────────────────────────────────────────────────────────────────────────────
   HOOKS / SMALL COMPONENTS
   ──────────────────────────────────────────────────────────────────────────── */

/** IntersectionObserver-based on-view hook (one-shot). */
function useOnView(ref, opts = { threshold: 0.4 }) {
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    if (!ref.current || seen) return
    const io = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) { setSeen(true); io.disconnect() }
    }, opts)
    io.observe(ref.current)
    return () => io.disconnect()
  }, [ref, seen, opts])
  return seen
}

/** Smooth count-up animation, only fires when its container is on-screen. */
function CountUp({ to, unit = '', durationMs = 1200 }) {
  const ref = useRef(null)
  const seen = useOnView(ref)
  const [val, setVal] = useState(0)
  useEffect(() => {
    if (!seen) return
    let start = null
    let raf = 0
    const tick = (t) => {
      if (start == null) start = t
      const p = Math.min(1, (t - start) / durationMs)
      const eased = 1 - Math.pow(1 - p, 3)
      setVal(Math.round(to * eased))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [seen, to, durationMs])
  return <span ref={ref} className="num">{val}{unit}</span>
}

/** Floating ToC + scroll-spy — sectioned rail with progress fill, numbers, and glow. */
function FloatingToc() {
  const [active, setActive] = useState('hero')
  const [progress, setProgress] = useState(0)
  const [hovered, setHovered] = useState(false)

  useEffect(() => {
    const sections = TOC.map(t => document.getElementById(t.id)).filter(Boolean)
    if (!sections.length) return
    const io = new IntersectionObserver((entries) => {
      const hit = entries.filter(e => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
      if (hit) setActive(hit.target.id)
    }, { rootMargin: '-25% 0px -55% 0px', threshold: [0.1, 0.5, 1] })
    sections.forEach(s => io.observe(s))

    const onScroll = () => {
      const h = document.documentElement
      const pct = h.scrollHeight - h.clientHeight > 0
        ? (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100 : 0
      setProgress(Math.min(100, Math.max(0, pct)))
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => { io.disconnect(); window.removeEventListener('scroll', onScroll) }
  }, [])

  const activeIdx = TOC.findIndex(t => t.id === active)

  return (
    <nav
      className="hidden lg:flex fixed right-5 top-1/2 -translate-y-1/2 z-40 items-stretch gap-3"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      aria-label="Page sections"
    >
      {/* Section list */}
      <ol className="flex flex-col gap-1 text-xs py-2 pr-1 transition-all"
        style={{
          background: hovered ? 'rgba(8,8,9,.85)' : 'transparent',
          borderRadius: 12,
          border: hovered ? '1px solid var(--border-2)' : '1px solid transparent',
          padding: hovered ? '10px 14px 10px 10px' : '8px 4px',
          backdropFilter: hovered ? 'blur(10px)' : 'none',
          boxShadow: hovered ? '0 12px 30px rgba(0,0,0,.4)' : 'none',
          minWidth: hovered ? 200 : 'auto',
        }}>
        {TOC.map((t, i) => {
          const on = active === t.id
          const past = i < activeIdx
          return (
            <li key={t.id}>
              <a href={`#${t.id}`}
                className="group flex items-center gap-3 py-1 transition-all rounded"
                style={{
                  color: on ? '#f87171' : past ? 'var(--text-3)' : 'var(--text-4)',
                  paddingLeft: hovered ? 6 : 0,
                  paddingRight: hovered ? 6 : 0,
                }}>
                <span className="font-mono num text-[9px] w-4 text-right shrink-0 transition-colors"
                  style={{ color: on ? 'var(--accent)' : past ? 'var(--text-4)' : 'var(--border-3)' }}>
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span className="rounded-full transition-all shrink-0"
                  style={{
                    width: on ? 28 : past ? 14 : 10,
                    height: on ? 3 : 2,
                    background: on ? 'var(--accent)' : past ? 'rgba(225,29,72,.5)' : 'var(--border-3)',
                    boxShadow: on ? '0 0 10px rgba(225,29,72,.7)' : 'none',
                  }} />
                <span className="transition-all whitespace-nowrap"
                  style={{
                    fontWeight: on ? 700 : 500,
                    opacity: hovered ? 1 : 0,
                    transform: hovered ? 'translateX(0)' : 'translateX(-4px)',
                    pointerEvents: hovered ? 'auto' : 'none',
                  }}>
                  {t.label}
                </span>
              </a>
            </li>
          )
        })}
      </ol>

      {/* Vertical progress rail */}
      <div className="self-stretch w-[3px] rounded-full overflow-hidden relative my-2"
        style={{ background: 'rgba(255,255,255,.04)' }}>
        <div className="absolute left-0 right-0 top-0 transition-all rounded-full"
          style={{
            height: `${progress}%`,
            background: 'linear-gradient(180deg, #fb7185, #e11d48, #9f1239)',
            boxShadow: '0 0 8px rgba(225,29,72,.6)',
          }} />
        <span className="absolute left-1/2 -translate-x-1/2 w-2 h-2 rounded-full transition-all"
          style={{
            top: `calc(${progress}% - 4px)`,
            background: '#fb7185',
            boxShadow: '0 0 10px rgba(251,113,133,.9)',
          }} />
      </div>
    </nav>
  )
}

/** Replays a fake "detection feed" — rows appear in sequence with a typed cursor. */
function LiveDemoConsole() {
  const FEED = [
    { sev: 'INFO',     t: 'connection.established',  d: 'srv-bastion-01 ⇄ 10.0.0.42', delay: 0 },
    { sev: 'INFO',     t: 'auth.failed',             d: 'user=admin src=198.51.100.42', delay: 380 },
    { sev: 'INFO',     t: 'auth.failed',             d: 'user=admin src=198.51.100.42', delay: 580 },
    { sev: 'INFO',     t: 'auth.failed',             d: 'user=admin src=198.51.100.42 (×3)', delay: 780 },
    { sev: 'MEDIUM',   t: 'rule.R001 → matched',     d: '5 fails / 60s · same src', delay: 1000 },
    { sev: 'INFO',     t: 'auth.success',            d: 'user=admin src=198.51.100.42', delay: 1300 },
    { sev: 'HIGH',     t: 'enrich.intel',            d: '198.51.100.42 · abuse=92/100 · 14 reports', delay: 1500 },
    { sev: 'CRITICAL', t: 'rule.R001 + R022 chained',d: 'brute + impossible-travel → incident A4F', delay: 1800 },
    { sev: 'CRITICAL', t: 'ai.score',                d: 'TP probability 0.94 · escalate now', delay: 2050 },
  ]
  const [idx, setIdx] = useState(0)
  const [playing, setPlaying] = useState(true)

  useEffect(() => {
    if (!playing) return
    if (idx >= FEED.length) {
      const id = setTimeout(() => setIdx(0), 2500)
      return () => clearTimeout(id)
    }
    const id = setTimeout(() => setIdx(i => i + 1), FEED[idx]?.delay || 300)
    return () => clearTimeout(id)
  }, [idx, playing])

  return (
    <div className="rounded-2xl gradient-border overflow-hidden" style={{ background: 'var(--surface)' }}>
      <div className="flex items-center justify-between px-4 py-2 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-2">
          <span className="dot-live" />
          <p className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>Live detection feed · simulation</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPlaying(p => !p)} className="text-[10px] inline-flex items-center gap-1 px-2 py-1 rounded border" style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
            {playing ? <><Pause size={10} /> Pause</> : <><Play size={10} /> Play</>}
          </button>
          <button onClick={() => setIdx(0)} className="text-[10px] px-2 py-1 rounded border" style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
            Replay
          </button>
        </div>
      </div>
      <div className="p-4 font-mono text-xs space-y-1 h-64 overflow-hidden">
        {FEED.slice(0, idx).map((row, i) => (
          <div key={i} className="flex items-center gap-2 fade-in">
            <span className="num text-[10px]" style={{ color: 'var(--text-4)' }}>
              {String(i + 1).padStart(2, '0')}
            </span>
            <span className={
              row.sev === 'CRITICAL' ? 'text-red-400 font-bold' :
              row.sev === 'HIGH'     ? 'text-rose-400' :
              row.sev === 'MEDIUM'   ? 'text-amber-300' :
              'text-zinc-500'
            }>
              [{row.sev.padEnd(8)}]
            </span>
            <span style={{ color: 'var(--text-1)' }}>{row.t}</span>
            <span className="truncate" style={{ color: 'var(--text-3)' }}>{row.d}</span>
          </div>
        ))}
        {idx < FEED.length && <span className="inline-block w-2 h-3 align-middle bg-rose-400 blink" />}
      </div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────────────────
   PAGE
   ──────────────────────────────────────────────────────────────────────────── */

export default function Landing() {
  const { session } = useSession()
  const navigate = useNavigate()
  const [openFaq, setOpenFaq] = useState(0)
  const [faqQuery, setFaqQuery] = useState('')
  const [capTab, setCapTab] = useState(0)
  const [autoplay, setAutoplay] = useState(true)
  const [hoverStep, setHoverStep] = useState(null)
  const [selectedTactic, setSelectedTactic] = useState(null)

  // Auto-rotate capability tabs (pauses on hover or manual click).
  useEffect(() => {
    if (!autoplay) return
    const id = setInterval(() => setCapTab(t => (t + 1) % CAPABILITY_TABS.length), 5000)
    return () => clearInterval(id)
  }, [autoplay])

  const filteredFaqs = useMemo(() => {
    if (!faqQuery.trim()) return FAQS
    const q = faqQuery.toLowerCase()
    return FAQS.filter(f => f.q.toLowerCase().includes(q) || f.a.toLowerCase().includes(q))
  }, [faqQuery])

  return (
    <div className="max-w-6xl mx-auto py-3 space-y-10 fade-in">
      <FloatingToc />

      {/* ── HERO ───────────────────────────────────────────────── */}
      <section id="hero" className="hero-bg text-center pt-4 pb-2">
        <div className="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-full border mb-5"
          style={{ background: 'rgba(225,29,72,.06)', borderColor: 'rgba(225,29,72,.3)', color: '#f87171' }}>
          <span className="dot-live" />
          <span className="font-semibold">Live demo · No signup · Drop a log to start</span>
        </div>
        <h1 className="text-5xl sm:text-7xl font-extrabold mb-4 tracking-tight leading-none">
          <span className="text-white">N<span style={{ color: 'var(--accent)' }}>O</span>CTRA</span>{' '}
          <span className="aurora-text">AI</span>
        </h1>
        <div className="flex items-center justify-center gap-3 mb-5">
          <span className="h-px w-12" style={{ background: 'linear-gradient(90deg, transparent, var(--accent))' }} />
          <p className="text-[11px] font-bold tracking-[0.3em] uppercase whitespace-nowrap" style={{ color: 'var(--accent)' }}>
            AI-Powered Autonomous SOC
          </p>
          <span className="h-px w-12" style={{ background: 'linear-gradient(90deg, var(--accent), transparent)' }} />
        </div>
        <p className="text-base sm:text-lg max-w-2xl mx-auto leading-relaxed" style={{ color: 'var(--text-2)' }}>
          A storageless security operations platform that turns a flat log file into
          <span style={{ color: 'var(--text-1)' }}> ranked, scored, MITRE-mapped incidents </span>
          — with autonomous AI triage, attack-chain correlation, and a forensic report in minutes, not hours.
        </p>

        <div className="mt-7 flex items-center justify-center gap-2 flex-wrap">
          <button onClick={() => navigate('/upload')}
            className="btn-accent px-6 py-3 text-sm rounded-full inline-flex items-center gap-2 hover-glow font-bold">
            <UploadIcon size={15} /> Open Ingestion Module
            <ChevronRight size={14} />
          </button>
          {session ? (
            <button onClick={() => navigate('/triage')}
              className="text-sm px-6 py-3 rounded-full border inline-flex items-center gap-2 transition-colors"
              style={{ borderColor: 'var(--border-2)', color: 'var(--text-1)', background: 'var(--surface)' }}>
              <ShieldAlert size={14} color="#f43f5e" /> Resume session ({session.alerts?.length || 0} alerts)
            </button>
          ) : (
            <a href="#how"
              className="text-sm px-6 py-3 rounded-full border inline-flex items-center gap-2 transition-colors"
              style={{ borderColor: 'var(--border-2)', color: 'var(--text-1)', background: 'var(--surface)' }}>
              <Eye size={14} /> See how it works
            </a>
          )}
        </div>

        {/* Animated count-up hero stats */}
        <div className="mt-9 grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-3xl mx-auto">
          {HERO_STATS.map(s => {
            const I = s.icon
            return (
              <div key={s.l} className="rounded-xl px-4 py-3 tile-lift gradient-border" style={{ background: 'var(--surface)' }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-bold uppercase tracking-widest" style={{ color: 'var(--text-3)' }}>{s.l}</span>
                  <I size={12} style={{ color: 'var(--accent)' }} />
                </div>
                <p className="text-2xl font-extrabold text-white kpi-value">
                  {s.invert && <span style={{ color: 'var(--text-3)', fontWeight: 600 }}>{'<'}</span>}
                  <CountUp to={s.v} unit={s.unit} />
                </p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-4)' }}>{s.sub}</p>
              </div>
            )
          })}
        </div>
      </section>

      {/* ── LIVE TICKER ───────────────────────────────────────── */}
      <section className="rounded-xl py-2 px-1 border ticker" style={{ background: 'rgba(8,8,9,.85)', borderColor: 'var(--border)' }}>
        <div className="ticker-track text-xs">
          {[...TICKER_ITEMS, ...TICKER_ITEMS].map((t, i) => (
            <div key={i} className="flex items-center gap-3 shrink-0">
              <span className={SEV_CLASS[t.sev]}>{t.sev}</span>
              <span className="font-mono" style={{ color: 'var(--text-2)' }}>{t.t}</span>
              <span style={{ color: 'var(--border-3)' }}>·</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── HOW IT WORKS / PIPELINE ─────────────────────────── */}
      <section id="how" className="rounded-2xl p-6 gradient-border" style={{ background: 'var(--surface)' }}>
        <div className="flex items-end justify-between mb-5 flex-wrap gap-2">
          <div>
            <p className="eyebrow">How it works</p>
            <h2 className="text-2xl font-extrabold text-white mt-1">Eight-stage detection pipeline</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>Hover any stage to focus the description.</p>
          </div>
          <button onClick={() => navigate('/upload')}
            className="text-xs px-3 py-1.5 rounded-lg border inline-flex items-center gap-1.5 transition-colors"
            style={{ borderColor: 'var(--border-2)', color: 'var(--text-1)', background: 'var(--surface-2)' }}>
            Try a demo log <ArrowRight size={11} />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          {PIPELINE.map((s, i) => {
            const I = s.icon
            const focused = hoverStep === i
            const dimmed  = hoverStep != null && !focused
            return (
              <div key={s.step}
                onMouseEnter={() => setHoverStep(i)}
                onMouseLeave={() => setHoverStep(null)}
                className="rounded-xl p-3 transition-all tile-lift cursor-pointer"
                style={{
                  background: focused ? 'rgba(225,29,72,.10)' : 'var(--surface-2)',
                  border: `1px solid ${focused ? 'rgba(225,29,72,.45)' : 'var(--border)'}`,
                  opacity: dimmed ? 0.4 : 1,
                  boxShadow: focused ? '0 8px 24px rgba(225,29,72,.20)' : 'none',
                }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-widest num" style={{ color: 'var(--text-4)' }}>{s.step}</span>
                  <I size={14} color={focused ? '#f87171' : '#f87171'} />
                </div>
                <p className="text-xs font-bold text-white">{s.label}</p>
                <p className="text-[10px] leading-tight mt-1 transition-all" style={{
                  color: focused ? 'var(--text-1)' : 'var(--text-3)',
                  maxHeight: focused ? '120px' : '36px',
                  overflow: 'hidden',
                }}>{s.desc}</p>
              </div>
            )
          })}
        </div>

        {/* Detailed focus card under the pipeline */}
        <div className="mt-4 rounded-xl px-4 py-3 text-xs" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', minHeight: 44 }}>
          {hoverStep != null ? (
            <span style={{ color: 'var(--text-2)' }}>
              <span className="font-mono mr-2" style={{ color: 'var(--accent)' }}>{PIPELINE[hoverStep].step}</span>
              <span className="text-white font-semibold">{PIPELINE[hoverStep].label}</span> — {PIPELINE[hoverStep].desc}
            </span>
          ) : (
            <span style={{ color: 'var(--text-4)' }}>Hover any stage above to read its description here.</span>
          )}
        </div>
      </section>

      {/* ── CAPABILITIES (interactive tabs with auto-rotation) ─ */}
      <section id="capabilities"
        onMouseEnter={() => setAutoplay(false)}
        onMouseLeave={() => setAutoplay(true)}>
        <div className="flex items-end justify-between mb-5 flex-wrap gap-2">
          <div>
            <p className="eyebrow">Capabilities</p>
            <h2 className="text-2xl font-extrabold text-white mt-1">Four core workflows, end-to-end</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>
              {autoplay
                ? <>Auto-rotating · hover to pause</>
                : <>Paused · move your cursor away to resume</>}
            </p>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setCapTab(t => (t - 1 + CAPABILITY_TABS.length) % CAPABILITY_TABS.length)}
              className="w-7 h-7 rounded-full border inline-flex items-center justify-center transition-colors"
              style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
              <ChevronLeft size={13} />
            </button>
            <button onClick={() => setCapTab(t => (t + 1) % CAPABILITY_TABS.length)}
              className="w-7 h-7 rounded-full border inline-flex items-center justify-center transition-colors"
              style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
              <ChevronRight size={13} />
            </button>
          </div>
        </div>

        <div className="rounded-2xl p-5 gradient-border" style={{ background: 'var(--surface)' }}>
          {/* Tab strip */}
          <div className="flex gap-1 flex-wrap mb-5">
            {CAPABILITY_TABS.map((c, i) => {
              const I = c.icon
              const on = capTab === i
              return (
                <button key={c.key} onClick={() => { setCapTab(i); setAutoplay(false) }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold transition-all"
                  style={{
                    background: on ? 'rgba(225,29,72,.10)' : 'transparent',
                    border: `1px solid ${on ? 'rgba(225,29,72,.40)' : 'var(--border-2)'}`,
                    color: on ? '#f87171' : 'var(--text-2)',
                  }}>
                  <I size={13} /> {c.label}
                </button>
              )
            })}
          </div>

          {/* Tab content */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="md:col-span-1">
              <h3 className="text-lg font-extrabold text-white">{CAPABILITY_TABS[capTab].title}</h3>
              <p className="text-sm mt-2 leading-relaxed" style={{ color: 'var(--text-2)' }}>{CAPABILITY_TABS[capTab].blurb}</p>
              <button onClick={() => navigate('/upload')}
                className="text-xs mt-4 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg btn-accent font-bold">
                Try {CAPABILITY_TABS[capTab].label} <ChevronRight size={11} />
              </button>
            </div>
            <ul className="md:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {CAPABILITY_TABS[capTab].bullets.map(b => (
                <li key={b} className="flex items-start gap-2 text-sm rounded-xl px-3 py-2.5 transition-all"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <CheckCircle2 size={14} className="shrink-0 mt-0.5" color="#f87171" />
                  <span style={{ color: 'var(--text-1)' }}>{b}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Progress dots */}
          <div className="flex justify-center gap-1.5 mt-5">
            {CAPABILITY_TABS.map((_, i) => (
              <button key={i} onClick={() => setCapTab(i)}
                className="rounded-full transition-all"
                style={{
                  width: capTab === i ? 22 : 6,
                  height: 6,
                  background: capTab === i ? 'var(--accent)' : 'var(--border-3)',
                }} />
            ))}
          </div>
        </div>
      </section>

      {/* ── MITRE COVERAGE (clickable matrix) ───────────────── */}
      <section id="mitre" className="rounded-2xl p-6 gradient-border" style={{ background: 'var(--surface)' }}>
        <div className="flex items-end justify-between mb-5 flex-wrap gap-2">
          <div>
            <p className="eyebrow">MITRE ATT&CK coverage</p>
            <h2 className="text-2xl font-extrabold text-white mt-1">All 12 enterprise tactics monitored</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>Click any tactic to see the detection rules covering it.</p>
          </div>
          <span className="text-xs num px-2.5 py-1 rounded-full border" style={{ background: 'rgba(74,222,128,.06)', borderColor: 'rgba(74,222,128,.3)', color: '#4ade80' }}>
            12 / 12 tactics · 25 rules
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          {MITRE_TACTICS.map(t => {
            const on = selectedTactic === t.code
            return (
              <button key={t.code}
                onClick={() => setSelectedTactic(s => s === t.code ? null : t.code)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl transition-all text-left"
                style={{
                  background: on ? 'rgba(225,29,72,.10)' : 'var(--surface-2)',
                  border: `1px solid ${on ? 'rgba(225,29,72,.45)' : 'var(--border)'}`,
                  boxShadow: on ? '0 6px 18px rgba(225,29,72,.18)' : 'none',
                }}>
                <CheckCircle2 size={14} color={on ? '#f87171' : '#4ade80'} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-white truncate">{t.name}</p>
                  <p className="text-[10px] font-mono num" style={{ color: 'var(--text-4)' }}>
                    {t.code} · {t.rules.length} rule{t.rules.length !== 1 ? 's' : ''}
                  </p>
                </div>
              </button>
            )
          })}
        </div>

        {/* Tactic detail tray */}
        {selectedTactic && (() => {
          const t = MITRE_TACTICS.find(x => x.code === selectedTactic)
          return (
            <div className="mt-4 rounded-xl p-4 fade-in" style={{ background: 'rgba(225,29,72,.05)', border: '1px solid rgba(225,29,72,.25)' }}>
              <div className="flex items-center justify-between mb-2">
                <p className="font-bold text-white">{t.name} <span className="font-mono text-xs num" style={{ color: 'var(--text-3)' }}>{t.code}</span></p>
                <button onClick={() => setSelectedTactic(null)} className="text-xs" style={{ color: 'var(--text-3)' }}>Clear ✕</button>
              </div>
              {t.rules.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {t.rules.map(r => (
                    <span key={r} className="text-xs px-2.5 py-1 rounded-lg font-mono num"
                      style={{ background: 'rgba(225,29,72,.12)', border: '1px solid rgba(225,29,72,.3)', color: '#f87171' }}>
                      {r}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-xs" style={{ color: 'var(--text-3)' }}>
                  Built-in rules don't currently cover this tactic — define a custom rule in the Rule Builder.
                </p>
              )}
            </div>
          )
        })()}
      </section>

      {/* ── L1 vs L2 ──────────────────────────────────────────── */}
      <section id="tiers" className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[
          {
            tier: 'L1', title: 'Tier-1 Analyst', icon: ShieldAlert, badge: 'tier-l1',
            tagline: 'Triage & Respond',
            body: 'A compact, queue-driven workspace optimized for shift work. Process the backlog, escalate confirmed threats, dismiss noise, hand off cleanly at the end of shift.',
            bullets: ['Live alert stream', 'Critical-first sorting', 'AI suggestions inline', 'Shift handover report'],
          },
          {
            tier: 'L2', title: 'Tier-2 Threat Analyst', icon: ShieldCheck, badge: 'tier-l2',
            tagline: 'Hunt & Correlate',
            body: 'A dense forensic workbench. Reconstruct multi-stage attacks, pivot into the entity graph, run hypothesis-driven hunts, and ship a full incident dossier.',
            bullets: ['Composite threat score', 'Kill-chain reconstruction', 'Forensic incident drill-down', 'Full IOC + raw-log report'],
          },
        ].map(c => {
          const I = c.icon
          return (
            <div key={c.tier} className="rounded-2xl p-6 tile-lift gradient-border" style={{ background: 'var(--surface)' }}>
              <div className="flex items-start justify-between mb-3">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center icon-3d-red">
                  <I size={22} color="#f43f5e" strokeWidth={1.6} />
                </div>
                <span className={`tier-badge ${c.badge}`}>
                  <I size={11} /> {c.tier}
                </span>
              </div>
              <p className="text-lg font-extrabold text-white">{c.title}</p>
              <p className="text-xs uppercase tracking-widest font-semibold mt-0.5" style={{ color: 'var(--accent)' }}>{c.tagline}</p>
              <p className="text-sm mt-3" style={{ color: 'var(--text-2)' }}>{c.body}</p>
              <ul className="mt-4 grid grid-cols-2 gap-2">
                {c.bullets.map(b => (
                  <li key={b} className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-3)' }}>
                    <CheckCircle2 size={12} color="#f87171" /> {b}
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
      </section>

      {/* ── DETECTION ENGINE PEEK ───────────────────────────── */}
      <section id="engine" className="rounded-2xl p-6 gradient-border" style={{ background: 'var(--surface)' }}>
        <div className="flex items-end justify-between mb-5 flex-wrap gap-2">
          <div>
            <p className="eyebrow">Detection engine</p>
            <h2 className="text-2xl font-extrabold text-white mt-1">42 rules across 12 MITRE ATT&CK tactics</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>A representative slice — the full set is visible in the Rules module once you start a session.</p>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          {[
            { id: 'R001', n: 'Brute Force',           t: 'Credential Access' },
            { id: 'R005', n: 'Data Exfiltration',     t: 'Exfiltration' },
            { id: 'R011', n: 'PowerShell Suspicious', t: 'Execution' },
            { id: 'R013', n: 'LSASS Access',          t: 'Credential Access' },
            { id: 'R018', n: 'Event Log Cleared',     t: 'Defense Evasion' },
            { id: 'R021', n: 'C2 Beaconing',          t: 'Command & Control' },
            { id: 'R023', n: 'Mass Encryption',       t: 'Impact' },
            { id: 'R026', n: 'IDS Signature',         t: 'Command & Control' },
            { id: 'R027', n: 'Cloud Exfil',           t: 'Exfiltration' },
            { id: 'R028', n: 'NRD Contact',           t: 'Command & Control' },
            { id: 'R029', n: 'Phishing Email',        t: 'Initial Access' },
            { id: 'R030', n: 'Cloud Admin Grant',     t: 'Persistence' },
            { id: 'R031', n: 'Masquerade Binary',     t: 'Defense Evasion' },
            { id: 'R033', n: 'Kerberoasting',         t: 'Credential Access' },
            { id: 'R034', n: 'Office → Shell',        t: 'Initial Access' },
            { id: 'R038', n: 'CloudTrail Tamper',     t: 'Defense Evasion' },
            { id: 'R040', n: 'SharePoint Mass DL',    t: 'Collection' },
            { id: 'R041', n: 'Geo Anomaly',           t: 'Initial Access' },
          ].map(r => (
            <div key={r.id} className="rounded-xl px-3 py-2.5 tile-lift" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-[10px] font-bold num" style={{ color: 'var(--accent)' }}>{r.id}</span>
                <AlertOctagon size={11} color="#f87171" />
              </div>
              <p className="text-xs font-bold text-white">{r.n}</p>
              <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-4)' }}>{r.t}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── LIVE DEMO CONSOLE ─────────────────────────────────── */}
      <section id="demo">
        <div className="mb-4">
          <p className="eyebrow">Live demo</p>
          <h2 className="text-2xl font-extrabold text-white mt-1">Watch a brute-force incident come together</h2>
          <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>
            Five failed logins → AbuseIPDB enrichment → impossible-travel correlation → AI escalation. Replay or pause.
          </p>
        </div>
        <LiveDemoConsole />
      </section>

      {/* ── SECURITY / PRIVACY ────────────────────────────────── */}
      <section id="security" className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { icon: Lock,        title: 'Storageless by design', body: 'Files parsed in memory. Cleared on session end. No disk, no DB, no third-party retention.' },
          { icon: Network,     title: 'Local-first ingest',    body: 'Raw logs never leave your browser-to-backend channel. Only alert envelopes reach the AI.' },
          { icon: ShieldCheck, title: 'Auditable verdicts',    body: 'Every TP/FP captures decision, reason, AI rationale and analyst note — exportable in the report.' },
        ].map((c, i) => {
          const I = c.icon
          return (
            <div key={i} className="rounded-2xl p-5 tile-lift" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
              <div className="flex items-center gap-3 mb-3">
                <I size={18} color="#4ade80" />
                <p className="font-bold text-white">{c.title}</p>
              </div>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-2)' }}>{c.body}</p>
            </div>
          )
        })}
      </section>

      {/* ── FAQ with search ───────────────────────────────────── */}
      <section id="faq">
        <div className="flex items-end justify-between mb-3 flex-wrap gap-2">
          <p className="eyebrow">Frequently asked</p>
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
            <input
              value={faqQuery}
              onChange={e => setFaqQuery(e.target.value)}
              placeholder="Search the FAQ…"
              className="text-xs pl-7 pr-3 py-1.5 rounded-lg outline-none"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-2)', color: 'var(--text-1)', minWidth: 220 }}
              onFocus={e => e.target.style.borderColor = 'var(--accent)'}
              onBlur={e => e.target.style.borderColor = 'var(--border-2)'}
            />
          </div>
        </div>
        <div className="rounded-2xl overflow-hidden" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
          {filteredFaqs.length === 0 && (
            <div className="px-5 py-6 text-sm text-center" style={{ color: 'var(--text-3)' }}>
              No matching questions — clear the search to see everything.
            </div>
          )}
          {filteredFaqs.map((f, i) => {
            const open = openFaq === i
            return (
              <div key={f.q} className="border-b last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                <button onClick={() => setOpenFaq(open ? -1 : i)}
                  className="w-full flex items-center gap-3 text-left px-5 py-4 transition-colors hover:bg-white/[0.02]">
                  <ChevronRight size={14} className="shrink-0 transition-transform" style={{
                    color: open ? '#f87171' : 'var(--text-3)',
                    transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
                  }} />
                  <span className="text-sm font-semibold text-white flex-1">{f.q}</span>
                  <Filter size={12} style={{ color: 'var(--text-4)' }} />
                </button>
                {open && (
                  <div className="px-5 pb-4 pl-12 fade-in">
                    <p className="text-sm leading-relaxed" style={{ color: 'var(--text-2)' }}>{f.a}</p>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* ── CTA ────────────────────────────────────────────────── */}
      <section className="rounded-2xl p-8 text-center gradient-border" style={{ background: 'linear-gradient(135deg, rgba(225,29,72,.06), rgba(159,18,57,.02))' }}>
        <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 icon-3d-red">
          <UploadIcon size={26} color="#f43f5e" strokeWidth={1.6} />
        </div>
        <h2 className="text-2xl sm:text-3xl font-extrabold text-white">Ready to triage your first incident?</h2>
        <p className="text-sm sm:text-base max-w-xl mx-auto mt-2" style={{ color: 'var(--text-2)' }}>
          Open the Ingestion Module. Drop a CSV or run the demo attack scenario. The platform takes it from there.
        </p>
        <div className="mt-5 inline-flex items-center gap-2 flex-wrap justify-center">
          <button onClick={() => navigate('/upload')}
            className="btn-accent px-6 py-3 text-sm rounded-full inline-flex items-center gap-2 hover-glow font-bold">
            <UploadIcon size={15} /> Open Ingestion Module <ChevronRight size={14} />
          </button>
          <span className="text-xs num" style={{ color: 'var(--text-4)' }}>
            <Clock size={11} className="inline-block mr-1 -mt-0.5" />
            takes about 90 seconds for the demo
          </span>
        </div>
      </section>
    </div>
  )
}
