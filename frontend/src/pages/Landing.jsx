/**
 * Landing — Overview page.
 *
 * Enterprise rewrite (v4.0): dense, restrained, semantic.
 *   • Above-the-fold telemetry — engine health, rule count (43), MITRE coverage.
 *   • A grid of capability cards (4 surfaces).
 *   • A 10-stage pipeline (+ XGBoost ML scan stage).
 *   • Four detection signals: rules + ML + UEBA + AI.
 *   • A MITRE coverage matrix in real data (43 rules, 13 tactics).
 *   • Self-upgrade cycle FAQ entry.
 *   • A focused FAQ.
 *
 * All navigation paths and the SessionCtx flow are unchanged from v3.1.
 */
import { useMemo, useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, ArrowRight, Bot, Crosshair, Database, FileBarChart,
  GitBranch, Globe, Layers, Lock, Network, ShieldAlert, ShieldCheck,
  Sparkles, Workflow, Eye, Cpu, Search, ChevronDown, ChevronRight,
  Filter as FilterIcon, ClipboardList, Zap, Play, Pause, TerminalSquare,
  TrendingUp, RotateCcw, BarChart2,
} from 'lucide-react'
import { useSession } from '../App'
import useApiHealth from '../utils/useApiHealth'
import useCountUp from '../utils/useCountUp'
import Card from '../components/ui/Card'
import SectionHeader from '../components/ui/SectionHeader'
import StatusPill from '../components/ui/StatusPill'
import Kbd from '../components/ui/Kbd'
import {
  DisplayHeading, Eyebrow, NumberedFeature, GhostCTA, GridBackdrop, Reveal, StatStrip, LogoStrip,
} from '../components/ui/Display'

/* ── DATA ─────────────────────────────────────────────────────────────────── */

// Metrics with a numeric `n` get a count-up; metrics without (or with a
// `prefix`) render statically. Format string lets us reuse the same loop
// for "42", "<50ms" and "0".
const HERO_METRICS = [
  { k: 'detection_rules',  n: 43, fmt: v => v.toString(),       l: 'Detection rules', s: 'R001 → R043 + XGBoost ML detector' },
  { k: 'mitre_tactics',    n: 12, fmt: v => v.toString(),       l: 'MITRE tactics',   s: 'Initial Access → Impact' },
  { k: 'detection_p50',    n: 50, fmt: v => `<${v}ms`,          l: 'Rule eval p50',   s: 'on a 100k-row log file' },
  { k: 'bytes_persisted',  n: 0,  fmt: () => '0',               l: 'Bytes persisted', s: 'storageless by design' },
]

function HeroMetric({ n, fmt, l, s }) {
  const { ref, value } = useCountUp(n, { duration: 800 })
  return (
    <div className="hero-metric-tile">
      <p className="ent-section-eyebrow">{l}</p>
      <p ref={ref} className="tabular font-semibold leading-none"
        style={{ fontSize: 'var(--fs-2xl)', color: 'var(--text-1)' }}>
        {fmt(value)}
      </p>
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{s}</p>
    </div>
  )
}

function HeroMotionPanel({ healthMeta }) {
  const motionEvents = [
    { label: 'INGEST', value: 'CSV / JSON / SYSLOG', sub: '8.4k events normalized' },
    { label: 'RULE HIT', value: 'R001 + R022', sub: 'brute force + impossible travel' },
    { label: 'AI SCORE', value: '0.94 TP', sub: 'SHAP confidence converged' },
    { label: 'CHAIN', value: 'INC-A4F', sub: 'kill-chain assembled' },
  ]

  const scanLogs = [
    { ts: '00:01', src: '198.51.100.42', msg: 'auth.failed user=admin' },
    { ts: '00:03', src: '198.51.100.42', msg: 'auth.failed user=admin' },
    { ts: '00:07', src: '10.0.0.42', msg: 'auth.success privileged session' },
    { ts: '00:11', src: 'geo.ip', msg: 'impossible travel signal' },
    { ts: '00:13', src: 'engine', msg: 'correlating evidence indices' },
    { ts: '00:16', src: 'ai.score', msg: 'true-positive probability 0.94' },
  ]

  return (
    <Card variant="elevated" padding="none" className="hero-motion-panel mt-16 mx-auto max-w-5xl text-left">
      <div className="hero-motion-topbar">
        <div className="hero-terminal-title">
          <span className="hero-terminal-path">noctra.engine</span>
          <span className="hero-terminal-mode">live log scan</span>
        </div>
        <StatusPill tone={healthMeta.tone} dot={healthMeta.dot} pulse={healthMeta.pulse}>
          {healthMeta.label}
        </StatusPill>
      </div>

      <div className="hero-motion-grid">
        <div className="hero-live-scan">
          <div className="hero-scan-header">
            <span>Live scan</span>
            <strong>INC-A4F</strong>
          </div>
          <div className="hero-scan-window">
            <div className="hero-scan-line" aria-hidden="true" />
            {scanLogs.map((log, index) => (
              <div className="hero-log-row" key={`${log.ts}-${log.msg}`} style={{ '--row-delay': `${index * 0.12}s` }}>
                <span className="hero-log-time">{log.ts}</span>
                <span className="hero-log-source">{log.src}</span>
                <span className="hero-log-message">{log.msg}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="hero-motion-feed">
          <div className="hero-feed-header">
            <span>Detection stream</span>
            <strong>LIVE</strong>
          </div>
          {motionEvents.map((event, index) => (
            <div className="hero-feed-row" key={event.label} style={{ '--row-delay': `${index * 0.16}s` }}>
              <span className="hero-feed-index">{String(index + 1).padStart(2, '0')}</span>
              <div>
                <span>{event.label}</span>
                <small>{event.sub}</small>
              </div>
              <strong>{event.value}</strong>
            </div>
          ))}
          <div className="hero-intel-strip">
            <span>MITRE TA0006</span>
            <span>UEBA +2.8σ</span>
            <span>ASN flagged</span>
          </div>
        </div>

        <div className="hero-motion-metrics">
          {HERO_METRICS.map(m => (
            <HeroMetric key={m.k} {...m} />
          ))}
        </div>
      </div>
    </Card>
  )
}

const CAPABILITIES = [
  {
    icon: ShieldAlert, title: 'AI-augmented triage',
    body: '0–100 TP probability per alert with SHAP rationale, evidence indices, and a one-click verdict workflow. Keyboard-first for analysts clearing 100 alerts/hour.',
    cta: { to: '/triage', label: 'Open triage queue', auth: true },
  },
  {
    icon: Zap, title: 'XGBoost ML detection layer',
    body: 'A second detection pass runs after all 43 rules. Trained on 68,655 labeled log records across 6 log formats — catches attacks that deterministic regexes miss. 519-feature vector (TF-IDF + hand-crafted + format). Retrains nightly via the self-upgrade pipeline.',
    cta: { to: '/upload', label: 'Run a log through it', auth: false },
  },
  {
    icon: Crosshair, title: 'Hypothesis-driven hunting',
    body: 'Saved templates for off-hours auth, large outbound, multi-host pivots. Compose typed filters or have the AI translate natural language into the DSL.',
    cta: { to: '/hunt', label: 'Open hunt console', auth: true },
  },
  {
    icon: ClipboardList, title: 'Custom detection rules',
    body: 'Four templates (brute, lateral, exfil, priv-esc). Multi-condition filters, MITRE technique, severity, and live-fire against the active session before commit.',
    cta: { to: '/rules', label: 'Open rule builder', auth: true },
  },
  {
    icon: Bot, title: 'Autonomous investigation agent',
    body: 'Multi-turn agent that pivots into timeline, IOCs and threat intel automatically. Always cites the evidence it used. Deterministic fallback if AI is unavailable.',
    cta: { to: '/triage', label: 'Investigate an alert', auth: true },
  },
  {
    icon: Workflow, title: 'Self-upgrading detection engine',
    body: '5-phase pipeline runs nightly: corpus analyse → rule synthesise → parser extraction → model retrain. Thresholds auto-tune for maximum F1. Field aliases expand from real log data. Only statistically meaningful improvements (ΔF1 ≥ 0.02) are applied. Trigger on demand: POST /admin/retrain.',
    cta: { to: '/upload', label: 'Try the engine', auth: false },
  },
]

const PIPELINE = [
  { n: '01', icon: Database,       label: 'Ingest',     body: 'Auto-detect format. CSV / JSON / syslog / EVTX / Apache / logfmt. Corpus-learned format signals applied.' },
  { n: '02', icon: Cpu,            label: 'Normalize',  body: '95+ aliases (corpus-learned) collapse cloud variants into canonical fields.' },
  { n: '03', icon: ShieldAlert,    label: 'Detect',     body: '43 deterministic rules + UEBA anomaly model + cross-event correlation. Thresholds hot-reloaded from rule_config.json.' },
  { n: '04', icon: TerminalSquare, label: 'ML Scan',    body: 'XGBoost detector (68k training records, 519 features) catches attacks rule regexes miss. ≥ 70% confidence fires an ML-* alert.' },
  { n: '05', icon: Sparkles,       label: 'Score',      body: 'AI per-alert TP probability with SHAP feature attribution.' },
  { n: '06', icon: Globe,          label: 'Enrich',     body: 'IP reputation, geo, ASN, hash lookup, MITRE mapping.' },
  { n: '07', icon: GitBranch,      label: 'Chain',      body: 'Correlate alerts into kill-chain narratives.' },
  { n: '08', icon: Layers,         label: 'Dedup',      body: 'Collapse identical alerts across rules and uploads.' },
  { n: '09', icon: Eye,            label: 'Triage',     body: 'L1 queue with drawer, playbook, AI suggestion, keyboard nav.' },
  { n: '10', icon: FileBarChart,   label: 'Report',     body: 'L1 shift handover or L2 forensic dossier · PDF export.' },
]

const MITRE_TACTICS = [
  { code: 'TA0001', name: 'Initial Access',       rules: ['R022','R024','R029','R034','R041'] },
  { code: 'TA0002', name: 'Execution',            rules: ['R011','R032'] },
  { code: 'TA0003', name: 'Persistence',          rules: ['R007','R017','R025','R030'] },
  { code: 'TA0004', name: 'Privilege Escalation', rules: ['R003'] },
  { code: 'TA0005', name: 'Defense Evasion',      rules: ['R012','R018','R019','R031','R035','R036','R037','R038'] },
  { code: 'TA0006', name: 'Credential Access',    rules: ['R001','R010','R013','R015','R016','R033'] },
  { code: 'TA0007', name: 'Discovery',            rules: ['R002','R042','R043'] },
  { code: 'TA0008', name: 'Lateral Movement',     rules: ['R004','R020'] },
  { code: 'TA0009', name: 'Collection',           rules: ['R039','R040'] },
  { code: 'TA0011', name: 'Command & Control',    rules: ['R014','R021','R026','R028'] },
  { code: 'TA0010', name: 'Exfiltration',         rules: ['R005','R027'] },
  { code: 'TA0040', name: 'Impact',               rules: ['R023'] },
]

const FAQS = [
  { q: 'Where does the AI scoring come from?',          a: 'Each alert is sent to a Gemini-backed classifier with the relevant context (rule, MITRE technique, timestamps, source IP behavior). The model returns a 0–1 TP probability plus a short rationale shown in the drawer. When Gemini is unavailable, a deterministic 10-signal heuristic scores instead and always explains itself.' },
  { q: 'Do I have to train it on my data?',             a: 'No. Rules and the AI classifier are pre-tuned. The Learning Insights tab refines per-session weighting based on your TP/FP feedback in real time, but it never persists.' },
  { q: 'What if my log format isn’t listed?',           a: 'The ingest engine attempts heuristic column extraction even for unknown CSVs. JSON and JSONL also work out-of-the-box. For ad-hoc formats the Rule Builder lets you define custom field maps.' },
  { q: 'How is detection accuracy >90%?',               a: 'Four layers combine: (1) 43 deterministic rules with tight thresholds and pre-set confidence floors, (2) XGBoost ML detector trained on 68k labeled records, (3) behavioral anomaly scoring per user/host, (4) AI re-scoring against MITRE context. Cross-signal alerts converge above 90% TP probability.' },
  { q: 'Does the engine get smarter over time?',        a: 'Yes — a 5-phase self-upgrade pipeline (corpus analyse → rule synthesise → parser extraction → model retrain) runs nightly and can be triggered on demand via POST /admin/retrain. Each cycle re-optimises detection thresholds for maximum F1, expands field aliases from real log data, and retrains the XGBoost model. Only statistically meaningful improvements (ΔF1 ≥ 0.02) are applied.' },
  { q: 'Is my data sent anywhere?',                     a: 'Only the alert envelope (rule, technique, timestamps, optional anonymised IP/user) is sent to the AI classifier — never raw log lines. Files stay in memory. Clear the session and the data is gone.' },
  { q: 'Can I bring my own detection rules?',           a: 'Yes — the Rule Builder ships with four templates (brute force, lateral movement, data exfiltration, privilege escalation). You can compose multi-condition filters, assign severity, and map a MITRE technique. Custom rules run alongside built-ins.' },
  { q: 'How does the L1 vs L2 split work?',             a: 'The dashboard ships two role lenses. L1 is queue-driven and concise — built for shift work. L2 is forensic and dense — composite threat score, kill-chain reconstruction, top entities, hypothesis-driven hunts. The role switch also changes the exported report template.' },
]

/* ── HEALTH → STATUSPILL TONE ─────────────────────────────────────────────── */
const TONE_BY_HEALTH = {
  online:   { tone: 'success', label: 'Engine online',   dot: true,  pulse: true },
  degraded: { tone: 'warning', label: 'Engine degraded', dot: true,  pulse: false },
  offline:  { tone: 'danger',  label: 'Engine offline',  dot: true,  pulse: false },
  checking: { tone: 'neutral', label: 'Connecting…',     dot: false, pulse: false },
}

/* ── LIVE TERMINAL ────────────────────────────────────────────────────────── */
const FEED = [
  { sev: 'INFO',     t: 'connection.established',   d: 'srv-bastion-01 ⇄ 10.0.0.42',                 delay: 0    },
  { sev: 'INFO',     t: 'auth.failed',               d: 'user=admin src=198.51.100.42',                delay: 420  },
  { sev: 'INFO',     t: 'auth.failed',               d: 'user=admin src=198.51.100.42',                delay: 620  },
  { sev: 'INFO',     t: 'auth.failed',               d: 'user=admin src=198.51.100.42 (×3)',           delay: 820  },
  { sev: 'MEDIUM',   t: 'rule.R001 → matched',       d: '5 failures / 60s · same source IP',          delay: 1050 },
  { sev: 'INFO',     t: 'auth.success',              d: 'user=admin src=198.51.100.42',                delay: 1350 },
  { sev: 'HIGH',     t: 'enrich.threatintel',        d: '198.51.100.42 · abuse=92/100 · 14 reports',  delay: 1580 },
  { sev: 'HIGH',     t: 'rule.R022 → matched',       d: 'impossible-travel · 3 geo in 8 min',         delay: 1820 },
  { sev: 'CRITICAL', t: 'chain.R001+R022 → incident',d: 'brute-force + travel correlated → INC-A4F',  delay: 2100 },
  { sev: 'CRITICAL', t: 'ai.score',                  d: 'TP probability 0.94 · ESCALATE IMMEDIATELY', delay: 2380 },
]

function LiveDemoConsole() {
  const [idx,     setIdx]     = useState(0)
  const [playing, setPlaying] = useState(true)

  useEffect(() => {
    if (!playing) return
    if (idx >= FEED.length) {
      const id = setTimeout(() => setIdx(0), 3000)
      return () => clearTimeout(id)
    }
    const id = setTimeout(() => setIdx(i => i + 1), FEED[idx]?.delay || 350)
    return () => clearTimeout(id)
  }, [idx, playing])

  const sevColor = (s) =>
    s === 'CRITICAL' ? '#f87171' :
    s === 'HIGH'     ? '#fb923c' :
    s === 'MEDIUM'   ? '#fbbf24' : '#52525b'

  return (
    <Card variant="elevated" padding="none" className="overflow-hidden">
      {/* Terminal titlebar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
        <div className="flex items-center gap-2.5">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#ef4444' }} />
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#f59e0b' }} />
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: '#22c55e' }} />
          </div>
          <div className="flex items-center gap-1.5 ml-1">
            <span className="dot-live" />
            <span className="text-[11px] font-bold tracking-[0.15em] uppercase" style={{ color: 'var(--text-3)' }}>
              noctra.engine — live detection simulation
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => { setPlaying(p => !p) }}
            className="inline-flex items-center gap-1 text-[10px] px-2 py-1 rounded border transition-colors"
            style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
            {playing ? <><Pause size={9} /> Pause</> : <><Play size={9} /> Play</>}
          </button>
          <button onClick={() => setIdx(0)}
            className="text-[10px] px-2 py-1 rounded border transition-colors"
            style={{ borderColor: 'var(--border-2)', color: 'var(--text-2)' }}>
            Replay
          </button>
        </div>
      </div>

      {/* Feed rows */}
      <div className="p-4 font-mono text-xs space-y-1.5 overflow-hidden" style={{ height: 260, background: 'var(--bg)' }}>
        {FEED.slice(0, idx).map((row, i) => (
          <div key={i} className="flex items-start gap-2.5 fade-in">
            <span className="shrink-0 tabular-nums" style={{ color: 'var(--text-5)' }}>
              {String(i + 1).padStart(2, '0')}
            </span>
            <span className="shrink-0 font-bold w-20" style={{ color: sevColor(row.sev) }}>
              [{row.sev}]
            </span>
            <span className="shrink-0" style={{ color: 'var(--text-1)' }}>{row.t}</span>
            <span className="truncate" style={{ color: 'var(--text-3)' }}>{row.d}</span>
          </div>
        ))}
        {idx < FEED.length && playing && (
          <span className="inline-block w-2 h-3.5 align-middle rounded-sm" style={{ background: 'var(--accent)', animation: 'blink 1s step-end infinite' }} />
        )}
        {idx >= FEED.length && (
          <div className="pt-2 text-[10px] tracking-widest uppercase" style={{ color: 'var(--accent)' }}>
            ■ incident INC-A4F raised · AI verdict: TRUE POSITIVE · escalated to L2
          </div>
        )}
      </div>
    </Card>
  )
}

/* ── PAGE ─────────────────────────────────────────────────────────────────── */

export default function Landing() {
  const { session } = useSession()
  const navigate    = useNavigate()
  const health      = useApiHealth()
  const healthMeta  = TONE_BY_HEALTH[health] || TONE_BY_HEALTH.checking

  const [faqQuery, setFaqQuery] = useState('')
  const [openFaq,  setOpenFaq]  = useState(0)
  const filteredFaqs = useMemo(() => {
    if (!faqQuery.trim()) return FAQS
    const q = faqQuery.toLowerCase()
    return FAQS.filter(f => f.q.toLowerCase().includes(q) || f.a.toLowerCase().includes(q))
  }, [faqQuery])

  const goPrimary = () => navigate(session ? '/triage' : '/upload')

  return (
    <div className="fade-in">

      {/* ─── HERO ─────────────────────────────────────────────────────── */}
      <GridBackdrop>
        <section id="hero" className="max-w-6xl mx-auto px-5 lg:px-8 text-center section-frame">
          <Reveal delay={80}>
            <DisplayHeading as="h1" size="lg" center wide>
              EVERY ALERT READ.{' '}
              <DisplayHeading.Accent>EVERY ATTACK MAPPED.</DisplayHeading.Accent>
            </DisplayHeading>
          </Reveal>

          <Reveal delay={160}>
            <p className="mx-auto mt-7 max-w-2xl text-base lg:text-lg"
              style={{ color: 'var(--text-2)', lineHeight: 1.6 }}>
              NOCTRA AI turns a flat log file into ranked, scored, MITRE-mapped incidents —
              with evidence indices, attack-chain correlation, automatic dedup, and a one-click
              forensic report. Built for L1 triage and L2 hunt.
            </p>
          </Reveal>

          <Reveal delay={240}>
            <div className="mt-10 flex flex-wrap items-center justify-center gap-x-10 gap-y-4">
              <GhostCTA onClick={goPrimary}>
                {session ? 'Open triage queue' : 'Launch operation'}
              </GhostCTA>
              <GhostCTA onClick={() => navigate('/upload')}>
                $ Run demo attack
              </GhostCTA>
            </div>
            <p className="mt-6 text-xs" style={{ color: 'var(--text-4)' }}>
              Press <Kbd>⌘</Kbd> <Kbd>K</Kbd> for the command palette
            </p>
          </Reveal>

          <Reveal delay={360}>
            <HeroMotionPanel healthMeta={healthMeta} />
          </Reveal>
        </section>
      </GridBackdrop>

      {/* ─── LOGO STRIP — sub-headline tactic markers ─────────────────── */}
      <div className="max-w-6xl mx-auto px-5 lg:px-8">
        <LogoStrip names={['INITIAL ACCESS', 'EXECUTION', 'PERSISTENCE', 'CRED ACCESS', 'LATERAL', 'EXFIL', 'C2', 'IMPACT']} />
      </div>

      {/* ─── CAPABILITIES ─────────────────────────────────────────────── */}
      <section id="capabilities" className="max-w-6xl mx-auto px-5 lg:px-8 section-frame">
        <Reveal>
          <span className="eyebrow-display">ONE PLATFORM, SIX SURFACES</span>
        </Reveal>
        <Reveal delay={80}>
          <DisplayHeading as="h2" size="md" className="mt-6">
            BUILT FOR THE QUEUE.
            <DisplayHeading.Muted>TUNED FOR THE HUNT.</DisplayHeading.Muted>
          </DisplayHeading>
        </Reveal>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-14">
          {CAPABILITIES.map((c, i) => {
            const disabled = c.cta.auth && !session
            return (
              <Reveal key={c.title} delay={i * 80}>
                <div className="feature-numbered h-full flex flex-col">
                  <Eyebrow num={i + 1} />
                  <h3 className="font-bold uppercase tracking-tight mt-4"
                    style={{ fontSize: '20px', color: 'var(--text-1)', letterSpacing: '-0.01em' }}>
                    {c.title}
                  </h3>
                  <p className="text-sm mt-3 flex-1" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
                    {c.body}
                  </p>
                  <div className="mt-6">
                    <button
                      disabled={disabled}
                      onClick={() => navigate(c.cta.to)}
                      className="cta-ghost disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {disabled ? 'Requires session' : c.cta.label} <span aria-hidden>→</span>
                    </button>
                  </div>
                </div>
              </Reveal>
            )
          })}
        </div>
      </section>

      {/* ─── PIPELINE ─────────────────────────────────────────────────── */}
      <section id="how" className="max-w-6xl mx-auto px-5 lg:px-8 section-frame">
        <Reveal>
          <span className="eyebrow-display">THE FULL STACK</span>
        </Reveal>
        <Reveal delay={80}>
          <DisplayHeading as="h2" size="md" className="mt-6">
            TEN STAGES.
            <DisplayHeading.Muted>ZERO BLACK BOXES.</DisplayHeading.Muted>
          </DisplayHeading>
        </Reveal>
        <Reveal delay={160}>
          <p className="mt-6 max-w-2xl text-sm" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
            Ingest → normalize → detect → ML scan → score → enrich → chain → dedup → triage → report. Every stage is observable, every score is explained. Plus a background self-upgrade cycle that retrains rules and the ML model nightly.
          </p>
        </Reveal>

        <div className="grid md:grid-cols-3 gap-4 mt-14">
          {PIPELINE.map((p, i) => (
            <Reveal key={p.n} delay={i * 50}>
              <div className="feature-numbered h-full">
                <Eyebrow num={parseInt(p.n, 10)} />
                <h3 className="font-bold uppercase tracking-tight mt-4"
                  style={{ fontSize: '17px', color: 'var(--text-1)' }}>
                  {p.label}
                </h3>
                <p className="text-xs mt-2" style={{ color: 'var(--text-3)', lineHeight: 1.55 }}>
                  {p.body}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ─── ML TRAINING HIGHLIGHT ────────────────────────────────────── */}
      <section id="ml-engine" className="max-w-6xl mx-auto px-5 lg:px-8 section-frame">
        <Reveal>
          <span className="eyebrow-display">ML DETECTION ENGINE</span>
        </Reveal>
        <Reveal delay={80}>
          <DisplayHeading as="h2" size="md" className="mt-6">
            TRAINED ON 68K RECORDS.
            <DisplayHeading.Muted>RETRAINS EVERY NIGHT.</DisplayHeading.Muted>
          </DisplayHeading>
        </Reveal>
        <Reveal delay={160}>
          <p className="mt-6 max-w-2xl text-sm" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
            A second detection pass runs <em>after</em> all 43 deterministic rules — catching attack patterns that
            regex rules miss. Trained on 68k labeled records across six log formats, retrained automatically every
            night so detection improves without a single code change.
          </p>
        </Reveal>

        {/* Stat strip — same card style as ENGINE section */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-12">
          {[
            { icon: Database,   label: 'Training corpus',  stat: '68,655',  sub: 'labeled log records · 6 formats' },
            { icon: BarChart2,  label: 'Feature vector',   stat: '519',     sub: '500 TF-IDF + 12 hand-crafted + 7 format' },
            { icon: TrendingUp, label: 'Model AUC',        stat: '1.00',    sub: 'held-out test split · XGBoost classifier' },
            { icon: RotateCcw,  label: 'Upgrade cadence',  stat: 'Nightly', sub: '5-phase pipeline · POST /admin/retrain' },
          ].map(({ icon: Icon, label, stat, sub }, idx) => (
            <Reveal key={label} delay={idx * 60}>
              <Card variant="elevated" padding="lg" className="lift">
                <div className="w-9 h-9 rounded-md flex items-center justify-center mb-3"
                  style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
                  <Icon size={16} />
                </div>
                <p className="ent-section-eyebrow">{label}</p>
                <p className="font-bold tabular mt-1.5 leading-none"
                  style={{ fontSize: 'var(--fs-2xl)', color: 'var(--text-1)' }}>{stat}</p>
                <p className="text-xs mt-1.5" style={{ color: 'var(--text-3)', lineHeight: 1.5 }}>{sub}</p>
              </Card>
            </Reveal>
          ))}
        </div>

        {/* Self-upgrade phase strip — same feature-numbered style as PIPELINE */}
        <Reveal delay={120}>
          <p className="ent-section-eyebrow mt-12 mb-5">5-phase self-upgrade cycle</p>
        </Reveal>
        <div className="grid sm:grid-cols-5 gap-3">
          {[
            { n: '01', label: 'Corpus Analyse',  body: 'F1-grid-search thresholds + mine discriminative bigrams per rule' },
            { n: '02', label: 'Rule Synthesise', body: 'Patch rule_config.json — only ΔF1 ≥ 0.02 changes applied' },
            { n: '03', label: 'Parser Extract',  body: 'Expand field aliases + format-detection signals from corpus' },
            { n: '04', label: 'Model Retrain',   body: 'Rebuild XGBoost pkl — hot-swapped into engine without restart' },
            { n: '✓',  label: 'Hot-reload',      body: 'Engine picks up new thresholds, aliases, and model on next call' },
          ].map((p, i) => (
            <Reveal key={p.n} delay={i * 50}>
              <div className="feature-numbered h-full">
                <Eyebrow num={p.n === '✓' ? '✓' : parseInt(p.n, 10)} />
                <h3 className="font-bold uppercase tracking-tight mt-4"
                  style={{ fontSize: '13px', color: 'var(--text-1)', letterSpacing: '0.02em' }}>
                  {p.label}
                </h3>
                <p className="text-xs mt-2" style={{ color: 'var(--text-3)', lineHeight: 1.55 }}>
                  {p.body}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* Original sections continue below — wrapped to preserve max-width. */}
      <div className="max-w-7xl mx-auto px-5 lg:px-8 pb-12 space-y-12">

      {/* ─── MITRE COVERAGE ───────────────────────────────────────────── */}
      <section id="mitre" className="section-frame-tight space-y-10">
        <SectionHeader
          variant="display-sm"
          eyebrow="ATT&CK COVERAGE"
          title="MAPPED TO MITRE."
          hint="43 rules across 13 tactics. Each row lists the rule IDs that fire under that tactic. Drilldown lives in the Dashboard → MITRE Coverage tab."
          level={2}
          right={
            <button onClick={() => navigate('/dashboard')}
              className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors"
              style={{ background: 'var(--info-dim)', border: '1px solid rgba(59,130,246,0.3)', color: '#60a5fa' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(59,130,246,0.15)'}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--info-dim)'}
            >
              <Network size={12} /> Open MITRE matrix
            </button>
          }
        />
        <Card padding="none" variant="elevated">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left" style={{ color: 'var(--text-3)' }}>
                  <th className="px-4 py-2.5 font-medium ent-section-eyebrow">Tactic</th>
                  <th className="px-4 py-2.5 font-medium ent-section-eyebrow">Code</th>
                  <th className="px-4 py-2.5 font-medium ent-section-eyebrow">Rules</th>
                  <th className="px-4 py-2.5 font-medium ent-section-eyebrow tabular text-right">Count</th>
                </tr>
              </thead>
              <tbody>
                {MITRE_TACTICS.map((t, i) => (
                  <tr key={t.code}
                    className="transition-colors hover:bg-[var(--surface-2)]"
                    style={{ borderTop: i === 0 ? 'none' : '1px solid var(--border)' }}>
                    <td className="px-4 py-3 font-medium" style={{ color: 'var(--text-1)' }}>{t.name}</td>
                    <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-3)' }}>{t.code}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {t.rules.map(r => (
                          <span key={r}
                            className="tabular font-mono text-[10.5px] px-1.5 py-0.5 rounded"
                            style={{
                              background: 'var(--surface-3)',
                              color: 'var(--text-2)',
                              border: '1px solid var(--border-2)',
                            }}>
                            {r}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 tabular text-right" style={{ color: 'var(--text-1)' }}>
                      {t.rules.length}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </section>

      {/* ─── LIVE TERMINAL (moved here — right after MITRE) ───────────── */}
      <section id="terminal" className="section-frame-tight space-y-8">
        <Reveal>
          <span className="eyebrow-display">LIVE SIMULATION</span>
        </Reveal>
        <Reveal delay={80}>
          <DisplayHeading as="h2" size="md" className="mt-6">
            WATCH A BRUTE-FORCE
            <DisplayHeading.Muted>BECOME AN INCIDENT.</DisplayHeading.Muted>
          </DisplayHeading>
        </Reveal>
        <Reveal delay={160}>
          <p className="text-sm max-w-2xl" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
            The engine detects, enriches, correlates and escalates — in real time.
            This simulation replays a multi-signal brute-force → impossible-travel kill chain.
          </p>
        </Reveal>
        <Reveal delay={240}>
          <LiveDemoConsole />
        </Reveal>
      </section>

      {/* ─── L1 vs L2 ─────────────────────────────────────────────────── */}
      <section id="tiers" className="section-frame-tight space-y-10">
        <Reveal>
          <SectionHeader
            variant="display-sm"
            eyebrow="ANALYST TIERS"
            title={<>ONE DASHBOARD.<DisplayHeading.Muted>TWO LENSES.</DisplayHeading.Muted></>}
            level={2}
          />
        </Reveal>
        <div className="grid md:grid-cols-2 gap-3">
          <Reveal delay={80}>
            <Card variant="elevated" padding="lg">
              <div className="flex items-center gap-2 mb-2">
                <StatusPill tone="accent">L1</StatusPill>
                <h3 className="font-semibold" style={{ color: 'var(--text-1)' }}>Triage analyst</h3>
              </div>
              <p className="text-sm" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>
                Queue-driven and concise. Built for a shift: rank, click, decide, export handover.
                Bulk verdicts, AI auto-apply on high-confidence alerts, keyboard shortcuts for
                every action. Optimised for clearing volume without losing context.
              </p>
              <ul className="text-sm mt-3 space-y-1.5" style={{ color: 'var(--text-2)' }}>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> Severity-ranked queue with AI recommendation</li>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> One-key TP/FP, bulk select, drawer-first detail</li>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> Shift handover PDF in one click</li>
              </ul>
            </Card>
          </Reveal>
          <Reveal delay={160}>
            <Card variant="elevated" padding="lg">
              <div className="flex items-center gap-2 mb-2">
                <StatusPill tone="info">L2</StatusPill>
                <h3 className="font-semibold" style={{ color: 'var(--text-1)' }}>Hunt analyst</h3>
              </div>
              <p className="text-sm" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>
                Forensic and dense. Composite threat score, kill-chain reconstruction, top entities,
                hypothesis-driven hunts, and the AI agent as a senior-analyst sidekick. The exported
                report becomes a full incident dossier.
              </p>
              <ul className="text-sm mt-3 space-y-1.5" style={{ color: 'var(--text-2)' }}>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> Attack-chain graph + timeline reconstruction</li>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> Hypothesis-driven hunting with typed DSL</li>
                <li className="flex items-center gap-2"><ChevronRight size={12} style={{ color: 'var(--accent)' }} /> L2 forensic dossier PDF with full evidence</li>
              </ul>
            </Card>
          </Reveal>
        </div>
      </section>

      {/* ─── ENGINE ───────────────────────────────────────────────────── */}
      <section id="engine" className="section-frame-tight space-y-10">
        <Reveal>
          <SectionHeader
            variant="display-sm"
            eyebrow="DETECTION ENGINE"
            title={<>FOUR SIGNALS.<DisplayHeading.Muted>ONE VERDICT.</DisplayHeading.Muted></>}
            hint="The score that lands on an analyst's desk is the agreement of four independent inputs."
            level={2}
          />
        </Reveal>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { i: ShieldAlert, t: 'Deterministic rules', d: '43 rule functions grouping events by attacker context (IP, user, device) and emitting one alert per group with sliding-window thresholds. Hot-reloadable via rule_config.json.' },
            { i: Cpu,         t: 'XGBoost ML detector', d: 'Trained on 68k labeled records. 519-feature vector (TF-IDF + hand-crafted + format). Fires on rows ≥ 70% confidence that rules missed. Retrained nightly.' },
            { i: Activity,    t: 'Behavioral anomaly',  d: 'IsolationForest UEBA model on per-user and per-IP features. Flags σ-deviation from baseline. Scored even if no rule fires.' },
            { i: Sparkles,    t: 'AI re-scoring',       d: 'Gemini classifier blended 70/30 with the deterministic heuristic. Returns a TP probability and structured rationale.' },
          ].map(({ i: Icon, t, d }, idx) => (
            <Reveal key={t} delay={idx * 80}>
              <Card variant="elevated" padding="lg" className="lift">
                <Icon size={18} style={{ color: 'var(--accent)' }} className="mb-3" />
                <p className="font-semibold mb-1.5" style={{ color: 'var(--text-1)' }}>{t}</p>
                <p className="text-sm" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>{d}</p>
              </Card>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ─── DEMO STRIP ───────────────────────────────────────────────── */}
      <Reveal>
        <section id="demo">
          <Card variant="elevated" padding="lg" className="overflow-hidden">
            <div className="flex flex-wrap gap-6 items-center justify-between">
              <div className="space-y-2 min-w-0 flex-1">
                <p className="ent-section-eyebrow">Live demo</p>
                <h3 className="text-xl font-semibold" style={{ color: 'var(--text-1)' }}>
                  A synthetic kill-chain in one click
                </h3>
                <p className="text-sm" style={{ color: 'var(--text-2)' }}>
                  Runs the same pipeline against a multi-stage attack scenario: brute force → privilege
                  escalation → lateral movement → exfiltration.
                </p>
              </div>
              <button
                onClick={() => navigate('/upload')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md font-semibold text-sm transition-colors"
                style={{ background: 'var(--accent)', color: '#fff', boxShadow: 'var(--elev-2)' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-hover)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent)')}
              >
                Run demo scenario <ArrowRight size={14} />
              </button>
            </div>
          </Card>
        </section>
      </Reveal>

      {/* ─── SECURITY ─────────────────────────────────────────────────── */}
      <section id="security" className="section-frame-tight space-y-10">
        <Reveal>
          <SectionHeader
            variant="display-sm"
            eyebrow="SECURITY"
            title={<>STORAGELESS.<DisplayHeading.Muted>INSPECTABLE.</DisplayHeading.Muted></>}
            level={2}
          />
        </Reveal>
        <div className="grid md:grid-cols-3 gap-3">
          {[
            { i: Lock,        t: 'Zero persistence',        d: 'Files are parsed in memory. Sessions evict after 30 min idle. No DB, no disk writes, nothing to subpoena.' },
            { i: ShieldCheck, t: 'Boundary minimal',        d: 'Only the alert envelope (rule, technique, timestamps, optional IPs/users) crosses the boundary to the AI classifier — never raw lines.' },
            { i: Workflow,    t: 'Every decision auditable', d: 'Each alert carries its rule ID, MITRE technique, evidence indices, and rationale. Verdicts log to the session in the same shape.' },
          ].map(({ i: Icon, t, d }, idx) => (
            <Reveal key={t} delay={idx * 80}>
              <Card padding="lg" className="lift">
                <Icon size={16} style={{ color: 'var(--accent)' }} className="mb-3" />
                <p className="font-semibold text-sm mb-1.5" style={{ color: 'var(--text-1)' }}>{t}</p>
                <p className="text-xs" style={{ color: 'var(--text-3)', lineHeight: 1.55 }}>{d}</p>
              </Card>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ─── FAQ ──────────────────────────────────────────────────────── */}
      <section id="faq" className="section-frame-tight space-y-10">
        <SectionHeader
          variant="display-sm"
          eyebrow="FAQ"
          title="QUESTIONS, ANSWERED."
          level={2}
          right={
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-3)' }} />
              <input
                type="text"
                placeholder="Search…"
                value={faqQuery}
                onChange={(e) => setFaqQuery(e.target.value)}
                aria-label="Search FAQs"
                className="pl-7 pr-3 py-1.5 rounded-md text-sm outline-none"
                style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--border-2)',
                  color: 'var(--text-1)',
                  width: 200,
                }}
              />
            </div>
          }
        />
        <Card padding="none">
          {filteredFaqs.length === 0 && (
            <div className="px-5 py-8 text-center text-sm" style={{ color: 'var(--text-3)' }}>
              No FAQ matches “{faqQuery}”.
            </div>
          )}
          {filteredFaqs.map((f, i) => {
            const open = openFaq === i
            return (
              <div key={f.q}
                style={{ borderTop: i === 0 ? 'none' : '1px solid var(--border)' }}>
                <button
                  onClick={() => setOpenFaq(open ? -1 : i)}
                  className="w-full text-left px-5 py-3.5 flex items-center justify-between gap-4 transition-colors"
                  style={{ color: 'var(--text-1)' }}
                  aria-expanded={open}
                >
                  <span className="text-sm font-medium">{f.q}</span>
                  <ChevronDown
                    size={15}
                    style={{
                      color: open ? 'var(--accent)' : 'var(--text-3)',
                      transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform .18s var(--ease)',
                    }}
                  />
                </button>
                {open && (
                  <div className="px-5 pb-4 text-sm" style={{ color: 'var(--text-2)', lineHeight: 1.6 }}>
                    {f.a}
                  </div>
                )}
              </div>
            )
          })}
        </Card>
      </section>

      {/* ─── CTA ──────────────────────────────────────────────────────── */}
      <section className="section-frame text-center">
        <Reveal>
          <span className="eyebrow-display">READY TO START</span>
        </Reveal>
        <Reveal delay={80}>
          <DisplayHeading as="h2" size="md" center wide className="mt-6">
            DROP A LOG.{' '}
            <DisplayHeading.Accent>WALK THE INCIDENT.</DisplayHeading.Accent>
          </DisplayHeading>
        </Reveal>
        <Reveal delay={160}>
          <p className="text-sm max-w-xl mx-auto mt-6" style={{ color: 'var(--text-3)' }}>
            No signup. No persistence. Session-scoped, in-memory, ephemeral.
          </p>
        </Reveal>
        <Reveal delay={240}>
          <div className="mt-10">
            <GhostCTA onClick={() => navigate('/upload')}>Open ingestion module</GhostCTA>
          </div>
        </Reveal>
      </section>
      </div>
    </div>
  )
}
