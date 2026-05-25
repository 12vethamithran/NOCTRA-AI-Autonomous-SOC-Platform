/**
 * Landing — Overview page.
 *
 * Enterprise rewrite (v3.2): dense, restrained, semantic. Drops the auto-
 * rotating capability tabs, floating ToC bling, count-up animations and
 * mixed-glow CTAs in favour of a Bloomberg/Linear/Splunk hybrid surface:
 *   • Above-the-fold telemetry — engine health, rule count, MITRE coverage.
 *   • A grid of capability cards rather than a single rotating panel.
 *   • A clean 9-stage pipeline (matches backend after the dedup pass).
 *   • A MITRE coverage matrix in real data, not faux dashboards.
 *   • A focused FAQ.
 *
 * All navigation paths and the SessionCtx flow are unchanged from v3.1.
 */
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, ArrowRight, Bot, Crosshair, Database, FileBarChart,
  GitBranch, Globe, Layers, Lock, Network, ShieldAlert, ShieldCheck,
  Sparkles, Workflow, Eye, Cpu, Search, ChevronDown, ChevronRight,
  Filter as FilterIcon, ClipboardList, Zap,
} from 'lucide-react'
import { useSession } from '../App'
import useApiHealth from '../utils/useApiHealth'
import useCountUp from '../utils/useCountUp'
import Card from '../components/ui/Card'
import SectionHeader from '../components/ui/SectionHeader'
import StatusPill from '../components/ui/StatusPill'
import Kbd from '../components/ui/Kbd'

/* ── DATA ─────────────────────────────────────────────────────────────────── */

// Metrics with a numeric `n` get a count-up; metrics without (or with a
// `prefix`) render statically. Format string lets us reuse the same loop
// for "42", "<50ms" and "0".
const HERO_METRICS = [
  { k: 'detection_rules',  n: 42, fmt: v => v.toString(),       l: 'Detection rules', s: 'R001 → R042 across MITRE ATT&CK' },
  { k: 'mitre_tactics',    n: 12, fmt: v => v.toString(),       l: 'MITRE tactics',   s: 'Initial Access → Impact' },
  { k: 'detection_p50',    n: 50, fmt: v => `<${v}ms`,          l: 'Rule eval p50',   s: 'on a 100k-row log file' },
  { k: 'bytes_persisted',  n: 0,  fmt: () => '0',               l: 'Bytes persisted', s: 'storageless by design' },
]

function HeroMetric({ n, fmt, l, s }) {
  const { ref, value } = useCountUp(n, { duration: 800 })
  return (
    <div className="space-y-1.5">
      <p className="ent-section-eyebrow">{l}</p>
      <p ref={ref} className="tabular font-semibold leading-none"
        style={{ fontSize: 'var(--fs-2xl)', color: 'var(--text-1)' }}>
        {fmt(value)}
      </p>
      <p className="text-xs" style={{ color: 'var(--text-3)' }}>{s}</p>
    </div>
  )
}

const CAPABILITIES = [
  {
    icon: ShieldAlert, title: 'AI-augmented triage',
    body: '0–100 TP probability per alert with SHAP rationale, evidence indices, and a one-click verdict workflow. Keyboard-first for analysts clearing 100 alerts/hour.',
    cta: { to: '/triage', label: 'Open triage queue', auth: true },
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
]

const PIPELINE = [
  { n: '01', icon: Database,     label: 'Ingest',    body: 'Auto-detect format. CSV / JSON / syslog / EVTX / Apache / logfmt.' },
  { n: '02', icon: Cpu,          label: 'Normalize', body: '40+ aliases collapse cloud variants into canonical fields.' },
  { n: '03', icon: ShieldAlert,  label: 'Detect',    body: '42 rules + UEBA anomaly model + cross-event correlation.' },
  { n: '04', icon: Sparkles,     label: 'Score',     body: 'AI per-alert TP probability with SHAP feature attribution.' },
  { n: '05', icon: Globe,        label: 'Enrich',    body: 'IP reputation, geo, ASN, hash lookup, MITRE mapping.' },
  { n: '06', icon: GitBranch,    label: 'Chain',     body: 'Correlate alerts into kill-chain narratives.' },
  { n: '07', icon: Layers,       label: 'Dedup',     body: 'Collapse identical alerts across rules and uploads.' },
  { n: '08', icon: Eye,          label: 'Triage',    body: 'L1 queue with drawer, playbook, AI suggestion, keyboard nav.' },
  { n: '09', icon: FileBarChart, label: 'Report',    body: 'L1 shift handover or L2 forensic dossier · PDF export.' },
]

const MITRE_TACTICS = [
  { code: 'TA0001', name: 'Initial Access',       rules: ['R022','R024','R029','R034','R041'] },
  { code: 'TA0002', name: 'Execution',            rules: ['R011','R032'] },
  { code: 'TA0003', name: 'Persistence',          rules: ['R007','R017','R025','R030'] },
  { code: 'TA0004', name: 'Privilege Escalation', rules: ['R003'] },
  { code: 'TA0005', name: 'Defense Evasion',      rules: ['R012','R018','R019','R031','R035','R036','R037','R038'] },
  { code: 'TA0006', name: 'Credential Access',    rules: ['R001','R010','R013','R015','R016','R033'] },
  { code: 'TA0007', name: 'Discovery',            rules: ['R002','R042'] },
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
  { q: 'How is detection accuracy >90%?',               a: 'Three layers combine: (1) deterministic rules with tight thresholds and pre-set confidence floors, (2) behavioral anomaly scoring per user/host, (3) AI re-scoring against MITRE context. Cross-signal alerts converge above 90% TP probability.' },
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
    <div className="max-w-7xl mx-auto px-5 lg:px-8 py-8 space-y-12 fade-in">

      {/* ─── HERO ─────────────────────────────────────────────────────── */}
      <section id="hero" className="space-y-6">
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill tone={healthMeta.tone} dot={healthMeta.dot} pulse={healthMeta.pulse}>
            {healthMeta.label}
          </StatusPill>
          <StatusPill tone="neutral">v3.2 · Storageless</StatusPill>
          {session && (
            <StatusPill tone="accent">Active session · {session.event_count?.toLocaleString()} events</StatusPill>
          )}
        </div>

        <div className="grid lg:grid-cols-[1.4fr_1fr] gap-8 items-start">
          <div className="space-y-5">
            <h1
              className="font-semibold leading-[1.05] tracking-tight"
              style={{ fontSize: 'clamp(36px, 5vw, 56px)', color: 'var(--text-1)' }}
            >
              The autonomous SOC for teams who
              <span style={{ color: 'var(--accent)' }}> read every alert</span>.
            </h1>
            <p className="text-base max-w-2xl" style={{ color: 'var(--text-2)', lineHeight: 1.6 }}>
              NOCTRA AI turns a flat log file into ranked, scored, MITRE-mapped incidents — with
              evidence indices, attack-chain correlation, automatic dedup, and a one-click forensic
              PDF report. Built for L1 triage and L2 hunt, with the AI accountable to the analyst.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                onClick={goPrimary}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md font-semibold text-sm transition-all"
                style={{
                  background: 'var(--accent)', color: '#fff',
                  boxShadow: 'var(--elev-2)',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-hover)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent)')}
              >
                {session ? 'Open triage queue' : 'Ingest a log file'}
                <ArrowRight size={14} />
              </button>
              <button
                onClick={() => navigate('/upload')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md font-semibold text-sm transition-colors"
                style={{
                  background: 'transparent', color: 'var(--text-1)',
                  border: '1px solid var(--border-2)',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                Run demo attack
              </button>
              <span className="text-xs ml-1" style={{ color: 'var(--text-3)' }}>
                Press <Kbd>⌘</Kbd> <Kbd>K</Kbd> for the command palette
              </span>
            </div>
          </div>

          {/* Hero metrics card */}
          <Card variant="elevated" padding="lg" className="space-y-4">
            <SectionHeader eyebrow="Platform telemetry" level={2}
              title={<span className="text-base font-semibold">At a glance</span>} />
            <div className="grid grid-cols-2 gap-4">
              {HERO_METRICS.map(m => (
                <HeroMetric key={m.k} {...m} />
              ))}
            </div>
            <div className="ent-divider" />
            <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-3)' }}>
              <span>Engine health</span>
              <StatusPill tone={healthMeta.tone} dot={healthMeta.dot} pulse={healthMeta.pulse}>
                {healthMeta.label}
              </StatusPill>
            </div>
          </Card>
        </div>
      </section>

      {/* ─── CAPABILITIES ─────────────────────────────────────────────── */}
      <section id="capabilities" className="space-y-5">
        <SectionHeader
          eyebrow="Capabilities"
          title="Four product surfaces. One session."
          hint="Every surface reads from the same in-RAM session — the same evidence the rules saw."
          level={2}
        />
        <div className="grid sm:grid-cols-2 gap-3">
          {CAPABILITIES.map(c => {
            const Icon = c.icon
            const disabled = c.cta.auth && !session
            return (
              <Card key={c.title} variant="elevated" padding="lg" className="flex flex-col lift ring-accent">
                <div className="flex items-start gap-3 mb-3">
                  <div
                    className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}
                  >
                    <Icon size={17} />
                  </div>
                  <div className="min-w-0">
                    <p className="font-semibold" style={{ color: 'var(--text-1)' }}>{c.title}</p>
                  </div>
                </div>
                <p className="text-sm flex-1" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>
                  {c.body}
                </p>
                <div className="mt-4 flex items-center justify-between">
                  <button
                    disabled={disabled}
                    onClick={() => navigate(c.cta.to)}
                    className="inline-flex items-center gap-1.5 text-sm font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    style={{ color: 'var(--accent)' }}
                  >
                    {disabled ? 'Requires session' : c.cta.label}
                    <ArrowRight size={13} />
                  </button>
                </div>
              </Card>
            )
          })}
        </div>
      </section>

      {/* ─── PIPELINE ─────────────────────────────────────────────────── */}
      <section id="how" className="space-y-5">
        <SectionHeader
          eyebrow="How it works"
          title="9-stage detection pipeline"
          hint="Ingest → normalize → detect → score → enrich → chain → dedup → triage → report. Every stage is observable and replaceable."
          level={2}
        />
        <div className="grid md:grid-cols-3 gap-2">
          {PIPELINE.map(p => {
            const Icon = p.icon
            return (
              <Card key={p.n} padding="md" className="flex gap-3 items-start lift">
                <div
                  className="w-8 h-8 rounded-md flex items-center justify-center shrink-0 tabular text-xs font-bold"
                  style={{ background: 'var(--surface-3)', color: 'var(--text-3)', border: '1px solid var(--border-2)' }}
                >
                  {p.n}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Icon size={13} style={{ color: 'var(--accent)' }} />
                    <p className="font-semibold text-sm" style={{ color: 'var(--text-1)' }}>{p.label}</p>
                  </div>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-3)', lineHeight: 1.5 }}>
                    {p.body}
                  </p>
                </div>
              </Card>
            )
          })}
        </div>
      </section>

      {/* ─── MITRE COVERAGE ───────────────────────────────────────────── */}
      <section id="mitre" className="space-y-5">
        <SectionHeader
          eyebrow="ATT&CK coverage"
          title="42 rules mapped to 12 MITRE tactics"
          hint="Each row lists the rule IDs that fire under that tactic. Drilldown lives in the Dashboard → MITRE Coverage tab."
          level={2}
          right={
            <StatusPill tone="info" icon={Network}>
              Open MITRE matrix
            </StatusPill>
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

      {/* ─── L1 vs L2 ─────────────────────────────────────────────────── */}
      <section id="tiers" className="space-y-5">
        <SectionHeader
          eyebrow="Analyst tiers"
          title="L1 triage and L2 hunt — one dashboard, two lenses"
          level={2}
        />
        <div className="grid md:grid-cols-2 gap-3">
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
        </div>
      </section>

      {/* ─── ENGINE ───────────────────────────────────────────────────── */}
      <section id="engine" className="space-y-5">
        <SectionHeader
          eyebrow="Detection engine"
          title="Three independent signal layers"
          hint="The score that lands on an analyst's desk is the agreement of these three independent inputs. Disagreement is what makes the dedup + chain stages worth running."
          level={2}
        />
        <div className="grid md:grid-cols-3 gap-3">
          {[
            { i: ShieldAlert, t: 'Deterministic rules', d: '42 rule functions grouping events by attacker context (IP, user, device) and emitting one alert per group with sliding-window thresholds.' },
            { i: Activity,    t: 'Behavioral anomaly',  d: 'IsolationForest UEBA model on per-user and per-IP features. Flags σ-deviation from baseline. Scored even if no rule fires.' },
            { i: Sparkles,    t: 'AI re-scoring',       d: 'Gemini classifier blended 70/30 with the deterministic heuristic. Returns a TP probability and structured rationale.' },
          ].map(({ i: Icon, t, d }) => (
            <Card key={t} variant="elevated" padding="lg" className="lift">
              <Icon size={18} style={{ color: 'var(--accent)' }} className="mb-3" />
              <p className="font-semibold mb-1.5" style={{ color: 'var(--text-1)' }}>{t}</p>
              <p className="text-sm" style={{ color: 'var(--text-2)', lineHeight: 1.55 }}>{d}</p>
            </Card>
          ))}
        </div>
      </section>

      {/* ─── DEMO STRIP ───────────────────────────────────────────────── */}
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
                escalation → lateral movement → exfiltration. Useful for evaluating before you upload
                production logs.
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

      {/* ─── SECURITY ─────────────────────────────────────────────────── */}
      <section id="security" className="space-y-5">
        <SectionHeader
          eyebrow="Security"
          title="Storageless. Stateless. Inspectable."
          level={2}
        />
        <div className="grid md:grid-cols-3 gap-3">
          {[
            { i: Lock,       t: 'Zero persistence', d: 'Files are parsed in memory. Sessions evict after 30 min idle. No DB, no disk writes, nothing to subpoena.' },
            { i: ShieldCheck,t: 'Boundary minimal', d: 'Only the alert envelope (rule, technique, timestamps, optional IPs/users) crosses the boundary to the AI classifier — never raw lines.' },
            { i: Workflow,   t: 'Every decision auditable', d: 'Each alert carries its rule ID, MITRE technique, evidence indices, and rationale. Verdicts log to the session in the same shape.' },
          ].map(({ i: Icon, t, d }) => (
            <Card key={t} padding="lg" className="lift">
              <Icon size={16} style={{ color: 'var(--accent)' }} className="mb-3" />
              <p className="font-semibold text-sm mb-1.5" style={{ color: 'var(--text-1)' }}>{t}</p>
              <p className="text-xs" style={{ color: 'var(--text-3)', lineHeight: 1.55 }}>{d}</p>
            </Card>
          ))}
        </div>
      </section>

      {/* ─── FAQ ──────────────────────────────────────────────────────── */}
      <section id="faq" className="space-y-5">
        <SectionHeader
          eyebrow="FAQ"
          title="Common questions"
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
      <section className="pt-2 pb-6">
        <Card variant="elevated" padding="xl" className="text-center">
          <p className="ent-section-eyebrow mb-2">Ready to start</p>
          <h3 className="text-2xl font-semibold mb-2" style={{ color: 'var(--text-1)' }}>
            Drop a log file and walk through an incident
          </h3>
          <p className="text-sm max-w-xl mx-auto mb-5" style={{ color: 'var(--text-3)' }}>
            No signup. No persistence. Session-scoped, in-memory, ephemeral.
          </p>
          <div className="inline-flex gap-3">
            <button
              onClick={() => navigate('/upload')}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md font-semibold text-sm transition-colors"
              style={{ background: 'var(--accent)', color: '#fff', boxShadow: 'var(--elev-2)' }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-hover)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'var(--accent)')}
            >
              Open ingestion module <ArrowRight size={14} />
            </button>
          </div>
        </Card>
      </section>
    </div>
  )
}
