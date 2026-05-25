import React, { useContext, useEffect, useState } from 'react'
import {
  SlidersHorizontal, Zap, Plus, X, Rocket, ListChecks, Lightbulb,
  ShieldPlus, Swords, Crosshair, ArrowUpCircle, Database,
} from 'lucide-react'
import { listCustomRules, createCustomRule, deleteCustomRule } from '../api/client'
import { useSession } from '../App'
import toast from 'react-hot-toast'

const TEMPLATE_ICON = {
  brute_force: Swords,
  lateral_movement: Crosshair,
  data_exfil: Database,
  privilege_escalation: ArrowUpCircle,
}

const RULE_TEMPLATES = [
  {
    id: 'brute_force',
    name: 'Brute Force Attack',
    description: 'Multiple failed login attempts from same source',
    severity: 'HIGH',
    conditions: [
      { field: 'event_type', operator: 'eq', value: 'login' },
      { field: 'status', operator: 'contains', value: 'FAIL' },
    ],
    logic: 'AND',
  },
  {
    id: 'lateral_movement',
    name: 'Lateral Movement',
    description: 'Same user accessing multiple hosts in short time',
    severity: 'HIGH',
    conditions: [
      { field: 'user', operator: 'eq', value: '' },
      { field: 'event_type', operator: 'eq', value: 'auth' },
    ],
    logic: 'AND',
  },
  {
    id: 'data_exfil',
    name: 'Data Exfiltration',
    description: 'Unusual outbound data transfer detected',
    severity: 'CRITICAL',
    conditions: [
      { field: 'bytes', operator: 'gte', value: '1000000' },
      { field: 'dest_ip', operator: 'ne', value: '10.0.0.0/8' },
    ],
    logic: 'AND',
  },
  {
    id: 'privilege_escalation',
    name: 'Privilege Escalation',
    description: 'Non-admin user accessing admin resources',
    severity: 'CRITICAL',
    conditions: [
      { field: 'event_type', operator: 'eq', value: 'admin' },
      { field: 'status', operator: 'eq', value: 'success' },
    ],
    logic: 'AND',
  },
]

const Card = ({ children, style = {} }) => (
  <div className="rounded-2xl p-6" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)', ...style }}>
    {children}
  </div>
)

const SectionHead = ({ title, icon: Icon }) => (
  <div className="flex items-center gap-3 mb-5">
    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
      <Icon size={16} />
    </div>
    <div>
      <span className="eyebrow-display">{title}</span>
    </div>
  </div>
)

export default function RuleBuilderPage() {
  const { session } = useSession()
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  const [formData, setFormData] = useState({
    id: '',
    name: '',
    description: '',
    severity: 'MEDIUM',
    mitre: '',
    conditions: [{ field: 'source_ip', operator: 'eq', value: '' }],
    logic: 'AND',
  })

  const fieldOptions = ['source_ip', 'dest_ip', 'user', 'event_type', 'status', 'bytes', 'port', 'timestamp', 'raw']
  const operatorOptions = ['eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'contains', 'startswith', 'in']
  const severityOptions = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  const logicOptions = ['AND', 'OR']

  useEffect(() => {
    const fetchRules = async () => {
      try {
        const res = await listCustomRules(session.session_id)
        setRules(res.data.rules || [])
      } catch (err) {
        console.error('Failed to fetch rules:', err)
        toast.error('Failed to load custom rules')
      }
    }

    if (session?.session_id) fetchRules()
  }, [session?.session_id])

  const handleAddCondition = () => {
    setFormData({
      ...formData,
      conditions: [...formData.conditions, { field: 'source_ip', operator: 'eq', value: '' }],
    })
  }

  const handleRemoveCondition = (idx) => {
    if (formData.conditions.length > 1) {
      setFormData({
        ...formData,
        conditions: formData.conditions.filter((_, i) => i !== idx),
      })
    } else {
      toast.error('At least one condition is required')
    }
  }

  const handleConditionChange = (idx, key, val) => {
    const newConditions = [...formData.conditions]
    newConditions[idx][key] = val
    setFormData({ ...formData, conditions: newConditions })
  }

  const applyTemplate = (template) => {
    setFormData({
      id: template.id.toUpperCase(),
      name: template.name,
      description: template.description,
      severity: template.severity,
      mitre: '',
      conditions: template.conditions,
      logic: template.logic,
    })
    toast.success(`Template "${template.name}" loaded ✓`)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccessMsg('')

    if (!formData.id || !formData.name) {
      setError('Rule ID and Name are required')
      return
    }

    if (!/^[A-Z0-9_]+$/.test(formData.id)) {
      setError('Rule ID must be uppercase alphanumeric with underscores')
      return
    }

    const validConditions = formData.conditions.filter((c) => c.field && c.operator && c.value)
    if (!validConditions.length) {
      setError('At least one complete condition is required')
      return
    }

    setLoading(true)
    try {
      const payload = {
        ...formData,
        conditions: validConditions,
      }
      const res = await createCustomRule(session.session_id, payload)

      setRules([...rules, payload])
      setSuccessMsg(`Rule "${formData.name}" created successfully! It will apply to all upcoming alerts.`)

      // Reset form
      setFormData({
        id: '',
        name: '',
        description: '',
        severity: 'MEDIUM',
        mitre: '',
        conditions: [{ field: 'source_ip', operator: 'eq', value: '' }],
        logic: 'AND',
      })

      setTimeout(() => setSuccessMsg(''), 4000)
    } catch (err) {
      const errMsg = err.response?.data?.detail || 'Failed to create rule'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteRule = async (ruleId) => {
    if (!window.confirm(`Delete rule ${ruleId}? It will no longer apply to new alerts.`)) return

    try {
      await deleteCustomRule(session.session_id, ruleId)
      setRules(rules.filter((r) => r.id !== ruleId))
      toast.success(`Rule ${ruleId} deleted ✓`)
    } catch (err) {
      toast.error('Failed to delete rule')
    }
  }

  const SEV_COLOR = {
    CRITICAL: { bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.3)', text: '#f87171' },
    HIGH: { bg: 'rgba(244,63,94,0.15)', border: 'rgba(244,63,94,0.3)', text: '#fb7185' },
    MEDIUM: { bg: 'rgba(225,29,72,0.15)', border: 'rgba(225,29,72,0.3)', text: '#f43f5e' },
    LOW: { bg: 'rgba(113,113,122,0.15)', border: 'rgba(113,113,122,0.3)', text: '#a1a1aa' },
  }

  return (
    <div className="space-y-6 fade-in pb-12">
      {/* Header */}
      <div>
        <span className="eyebrow-display">CUSTOM RULE BUILDER</span>
        <h1 className="display display-sm mt-3" style={{ color: 'var(--text-1)' }}>
          DETECTION, AUTHORED.
        </h1>
        <p className="text-sm mt-4 max-w-2xl" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
          Create detection rules without code. Rules apply automatically to all upcoming alerts.
        </p>
      </div>

      {/* Quick Templates */}
      <div className="bg-gradient-to-r from-purple-900/20 to-pink-900/20 rounded-2xl border border-purple-500/20 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center icon-3d-red">
            <Zap size={18} className="text-white" />
          </div>
          <div>
            <p className="font-bold text-white">Rule Templates</p>
            <p className="text-sm" style={{ color: 'var(--text-3)' }}>Start with a preset detection pattern</p>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {RULE_TEMPLATES.map(t => {
            const TIcon = TEMPLATE_ICON[t.id] || ShieldPlus
            const active = formData.id === t.id.toUpperCase()
            return (
              <button
                key={t.id}
                onClick={() => applyTemplate(t)}
                className="p-3 rounded-xl border text-left transition-all hover:bg-white/5"
                style={{
                  background: active ? 'rgba(225,29,72,0.1)' : 'var(--surface-2)',
                  borderColor: active ? 'rgba(225,29,72,0.4)' : 'var(--border)',
                }}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: 'rgba(225,29,72,0.12)', border: '1px solid rgba(225,29,72,0.25)' }}
                  >
                    <TIcon size={15} style={{ color: 'var(--accent)' }} />
                  </div>
                  <div className="font-semibold text-sm text-white">{t.name}</div>
                </div>
                <div className="text-xs" style={{ color: 'var(--text-4)' }}>{t.description}</div>
              </button>
            )
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form */}
        <div className="lg:col-span-2">
          <Card>
            <SectionHead title="Create New Rule" icon={ShieldPlus} />

            <form onSubmit={handleSubmit} className="space-y-5">
              {/* ID & Severity */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                    Rule ID
                  </label>
                  <input
                    type="text"
                    value={formData.id}
                    onChange={(e) => setFormData({ ...formData, id: e.target.value.toUpperCase() })}
                    placeholder="CR_001"
                    className="w-full px-3 py-2.5 rounded-lg border text-sm"
                    style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                  />
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-4)' }}>Uppercase alphanumeric + underscores</p>
                </div>
                <div>
                  <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                    Severity
                  </label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    className="w-full px-3 py-2.5 rounded-lg border text-sm"
                    style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                  >
                    {severityOptions.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Name */}
              <div>
                <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                  Rule Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g., Suspicious Port Access"
                  className="w-full px-3 py-2.5 rounded-lg border text-sm"
                  style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                />
              </div>

              {/* Description */}
              <div>
                <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                  Description (optional)
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Describe what this rule detects and why..."
                  rows={2}
                  className="w-full px-3 py-2.5 rounded-lg border text-sm resize-none"
                  style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                />
              </div>

              {/* MITRE */}
              <div>
                <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                  MITRE Technique (optional)
                </label>
                <input
                  type="text"
                  value={formData.mitre}
                  onChange={(e) => setFormData({ ...formData, mitre: e.target.value })}
                  placeholder="e.g., T1110, T1550"
                  className="w-full px-3 py-2.5 rounded-lg border text-sm"
                  style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                />
              </div>

              {/* Logic */}
              <div>
                <label className="text-xs font-bold uppercase tracking-widest mb-2 block" style={{ color: 'var(--text-3)' }}>
                  Condition Logic
                </label>
                <div className="flex gap-3">
                  {logicOptions.map((logic) => (
                    <label key={logic} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="logic"
                        value={logic}
                        checked={formData.logic === logic}
                        onChange={(e) => setFormData({ ...formData, logic: e.target.value })}
                        className="w-4 h-4"
                      />
                      <span className="text-sm font-semibold">{logic}</span>
                    </label>
                  ))}
                </div>
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-4)' }}>
                  AND = all conditions must match | OR = any condition can match
                </p>
              </div>

              {/* Conditions */}
              <div className="pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <label className="text-xs font-bold uppercase tracking-widest mb-3 block" style={{ color: 'var(--text-3)' }}>
                  Conditions ({formData.conditions.length})
                </label>
                <div className="space-y-3">
                  {formData.conditions.map((cond, idx) => (
                    <div key={idx} className="flex gap-2 items-end">
                      <select
                        value={cond.field}
                        onChange={(e) => handleConditionChange(idx, 'field', e.target.value)}
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      >
                        <option value="">— Field —</option>
                        {fieldOptions.map((f) => (
                          <option key={f} value={f}>{f}</option>
                        ))}
                      </select>
                      <select
                        value={cond.operator}
                        onChange={(e) => handleConditionChange(idx, 'operator', e.target.value)}
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      >
                        <option value="">— Op —</option>
                        {operatorOptions.map((op) => (
                          <option key={op} value={op}>{op}</option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={cond.value}
                        onChange={(e) => handleConditionChange(idx, 'value', e.target.value)}
                        placeholder="Value"
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      />
                      {formData.conditions.length > 1 && (
                        <button
                          type="button"
                          onClick={() => handleRemoveCondition(idx)}
                          className="px-3 py-2.5 rounded-lg font-bold transition-all"
                          style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={handleAddCondition}
                  className="mt-3 text-sm font-semibold px-4 py-2 rounded-lg transition-all inline-flex items-center gap-1.5"
                  style={{ background: 'rgba(99,102,241,0.15)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)' }}
                >
                  <Plus size={14} /> Add Condition
                </button>
              </div>

              {/* Errors & Success */}
              {error && (
                <div className="p-3 rounded-lg text-sm" style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}>
                  {error}
                </div>
              )}
              {successMsg && (
                <div className="p-3 rounded-lg text-sm" style={{ background: 'rgba(34,197,94,0.15)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' }}>
                  ✓ {successMsg}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg font-bold text-white transition-all"
                style={{
                  background: loading ? 'rgba(225,29,72,0.3)' : 'linear-gradient(135deg,#9f1239,#e11d48)',
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Creating Rule...
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <Rocket size={16} /> Create &amp; Deploy Rule
                  </span>
                )}
              </button>

              <p className="text-xs text-center" style={{ color: 'var(--text-4)' }}>
                Rules are immediately active and apply to all future alerts in this session and beyond.
              </p>
            </form>
          </Card>
        </div>

        {/* Active Rules Sidebar */}
        <div>
          <Card>
            <SectionHead title="Active Rules" icon={ListChecks} />

            {rules.length === 0 ? (
              <div className="text-center py-8" style={{ color: 'var(--text-3)' }}>
                <p className="text-sm mb-2">No custom rules yet</p>
                <p className="text-xs">Create your first rule to get started</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                {rules.map((rule) => {
                  const sev = SEV_COLOR[rule.severity] || SEV_COLOR.LOW
                  return (
                    <div
                      key={rule.id}
                      className="p-4 rounded-xl border transition-all hover:border-opacity-100"
                      style={{
                        background: sev.bg,
                        border: `1px solid ${sev.border}`,
                      }}
                    >
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div className="flex-1">
                          <div className="font-semibold text-sm" style={{ color: sev.text }}>
                            {rule.name}
                          </div>
                          <div className="text-xs mt-0.5 font-mono" style={{ color: 'var(--text-4)' }}>
                            {rule.id}
                          </div>
                        </div>
                        <span
                          className="text-xs font-bold px-2 py-0.5 rounded whitespace-nowrap"
                          style={{
                            background: sev.bg,
                            color: sev.text,
                            border: `1px solid ${sev.border}`,
                          }}
                        >
                          {rule.severity}
                        </span>
                      </div>

                      {rule.description && (
                        <p className="text-xs mb-2" style={{ color: 'var(--text-3)' }}>
                          {rule.description}
                        </p>
                      )}

                      <div className="text-xs space-y-1 mb-3" style={{ color: 'var(--text-4)' }}>
                        <div>
                          <span className="font-semibold">Conditions:</span> {rule.conditions?.length || 0} ({rule.logic})
                        </div>
                        {rule.mitre && (
                          <div>
                            <span className="font-semibold">MITRE:</span> {rule.mitre}
                          </div>
                        )}
                      </div>

                      <button
                        onClick={() => handleDeleteRule(rule.id)}
                        className="w-full py-1.5 rounded-lg text-xs font-bold transition-all"
                        style={{
                          background: 'rgba(239,68,68,0.15)',
                          color: '#f87171',
                          border: '1px solid rgba(239,68,68,0.3)',
                        }}
                      >
                        Delete Rule
                      </button>
                    </div>
                  )
                })}
              </div>
            )}
          </Card>

          {/* Info Card */}
          <Card style={{ background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)', marginTop: '1.5rem' }}>
            <p className="text-xs font-bold uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
              <Lightbulb size={13} style={{ color: 'var(--accent)' }} /> Tips
            </p>
            <ul className="space-y-1.5 text-xs" style={{ color: 'var(--text-2)' }}>
              <li>• Rules deploy instantly to all alerts</li>
              <li>• Use AND for stricter matching</li>
              <li>• Use OR for broader detection</li>
              <li>• Test with small datasets first</li>
              <li>• Monitor FP feedback in Dashboard</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  )
}
