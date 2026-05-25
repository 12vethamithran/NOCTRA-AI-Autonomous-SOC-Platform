import React, { useEffect, useState } from 'react'
import {
  Search, Zap, SlidersHorizontal, BarChart3, Crosshair,
  Lightbulb, Sparkles, Loader2, Plus, X, Wand2,
} from 'lucide-react'
import { getHuntTemplates, executeHunt, saveHuntAlert, nlHunt } from '../api/client'
import { useSession } from '../App'
import toast from 'react-hot-toast'

const HUNT_TEMPLATE_DEFS = [
  { id: 'off_hours', name: 'Off-Hours Logins', description: 'Detect user login activity outside business hours', fields: { event_type: 'login', status: 'success' } },
  { id: 'large_outbound', name: 'Large Data Outbound', description: 'Find unusual outbound data transfers', fields: { bytes: '1000000', dest_ip: '!' } },
  { id: 'multi_auth', name: 'Multi-Host Auth', description: 'Users authenticating to multiple hosts rapidly', fields: { event_type: 'auth', user: '' } },
  { id: 'failed_success', name: 'Failed→Success', description: 'Failed logins followed by successful ones', fields: { status: 'FAILED', event_type: 'login' } },
  { id: 'port_sweep', name: 'Port Sweep', description: 'Scanning activity across multiple ports', fields: { source_ip: '', dest_ip: '' } },
  { id: 'new_admin', name: 'New Admin Account', description: 'New administrative account creation', fields: { event_type: 'admin_create', user: '' } },
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

export default function HuntPage() {
  const { session, setSession } = useSession()
  const [selectedTemplate, setSelectedTemplate] = useState('')
  const [filters, setFilters] = useState([{ field: 'source_ip', operator: 'eq', value: '' }])
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [nlText, setNlText] = useState('')
  const [nlLoading, setNlLoading] = useState(false)
  const [interpretation, setInterpretation] = useState('')

  // Pivot hand-off: the AI agent can send the analyst here with prefilled filters.
  useEffect(() => {
    if (session?.pendingHuntFilters?.length) {
      setFilters(session.pendingHuntFilters.map(f => ({
        field: f.field, operator: f.operator, value: String(f.value ?? ''),
      })))
      setSession(s => ({ ...s, pendingHuntFilters: null }))
      toast.success('Pivot hunt loaded from AI agent')
    }
  }, [])

  const handleNlHunt = async () => {
    if (!session?.session_id) { toast.error('No active session'); return }
    if (!nlText.trim()) { toast.error('Describe what you want to hunt for'); return }
    setNlLoading(true)
    setError('')
    setInterpretation('')
    try {
      const { data } = await nlHunt(session.session_id, nlText.trim())
      const t = data.translation
      if (t?.filters?.length) {
        setFilters(t.filters.map(f => ({ field: f.field, operator: f.operator, value: String(f.value ?? '') })))
      }
      setInterpretation(t?.interpretation || '')
      setResults(data)
      if (!t?.filters?.length) {
        toast.error(t?.interpretation || 'Could not translate that request')
      } else {
        toast.success(`Translated → ${data.row_count} matching rows`)
      }
    } catch (err) {
      const msg = err.response?.data?.detail || 'Natural-language hunt failed'
      setError(msg)
      toast.error(msg)
    } finally {
      setNlLoading(false)
    }
  }

  const fieldOptions = ['source_ip', 'dest_ip', 'user', 'event_type', 'status', 'bytes', 'port', 'timestamp', 'raw']
  const operatorOptions = ['eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'contains', 'startswith', 'in']

  const handleAddFilter = () => {
    setFilters([...filters, { field: 'source_ip', operator: 'eq', value: '' }])
  }

  const handleRemoveFilter = (idx) => {
    if (filters.length > 1) {
      setFilters(filters.filter((_, i) => i !== idx))
    } else {
      toast.error('At least one filter is required')
    }
  }

  const handleFilterChange = (idx, key, val) => {
    const newFilters = [...filters]
    newFilters[idx][key] = val
    setFilters(newFilters)
  }

  const applyTemplate = (templateId) => {
    const template = HUNT_TEMPLATE_DEFS.find(t => t.id === templateId)
    if (template) {
      setSelectedTemplate(templateId)
      const templateFilters = Object.entries(template.fields).map(([field, value]) => ({
        field,
        operator: value.startsWith('!') ? 'ne' : 'eq',
        value: value.startsWith('!') ? value.slice(1) : value,
      }))
      setFilters(templateFilters)
      toast.success(`Template "${template.name}" applied ✓`)
    }
  }

  const handleExecuteHunt = async () => {
    if (!session?.session_id) {
      toast.error('No active session')
      return
    }

    const validFilters = filters.filter(f => f.field && f.operator && f.value)
    if (validFilters.length === 0) {
      toast.error('Please add at least one filter with values')
      return
    }

    setLoading(true)
    setError('')
    try {
      const res = await executeHunt(session.session_id, { filters: validFilters })
      setResults(res.data)
      toast.success(`Hunt executed: ${res.data.row_count} matching rows found`)
    } catch (err) {
      const errMsg = err.response?.data?.detail || 'Hunt execution failed'
      setError(errMsg)
      toast.error(errMsg)
    } finally {
      setLoading(false)
    }
  }

  const handleSaveAlert = async (alertDict) => {
    if (!session?.session_id) {
      toast.error('No active session')
      return
    }
    try {
      await saveHuntAlert(session.session_id, alertDict)
      toast.success('Alert saved to queue ✓')
    } catch (err) {
      toast.error('Failed to save alert')
    }
  }

  return (
    <div className="space-y-6 fade-in pb-12">
      {/* Header */}
      <div>
        <span className="eyebrow-display">THREAT HUNT MODE</span>
        <h1 className="display display-sm mt-3" style={{ color: 'var(--text-1)' }}>
          HUNT THE HYPOTHESIS.
        </h1>
        <p className="text-sm mt-4 max-w-2xl" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
          Write hypothesis-driven queries to proactively hunt for threats across your logs.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar: Templates */}
        <div className="lg:col-span-1 space-y-4">
          <Card>
            <SectionHead title="Quick Templates" icon={Zap} />
            <div className="space-y-2">
              {HUNT_TEMPLATE_DEFS.map(t => (
                <button
                  key={t.id}
                  onClick={() => applyTemplate(t.id)}
                  className="w-full text-left px-3 py-3 rounded-xl transition-all border"
                  style={{
                    background: selectedTemplate === t.id ? 'rgba(225,29,72,0.15)' : 'var(--surface-2)',
                    borderColor: selectedTemplate === t.id ? 'rgba(225,29,72,0.4)' : 'var(--border)',
                    color: selectedTemplate === t.id ? '#f87171' : 'var(--text-1)',
                  }}
                >
                  <div className="font-semibold text-sm">{t.name}</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-3)' }}>{t.description}</div>
                </button>
              ))}
            </div>
          </Card>

          {/* Stats */}
          {results && (
            <Card style={{ background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)' }}>
              <p className="text-xs font-bold uppercase tracking-widest mb-3" style={{ color: 'var(--text-3)' }}>Hunt Results</p>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span style={{ color: 'var(--text-3)' }}>Matching Rows</span>
                  <span className="font-bold text-white">{results.row_count}</span>
                </div>
                {results.statistics?.by_source_ip && (
                  <div className="flex justify-between">
                    <span style={{ color: 'var(--text-3)' }}>Unique IPs</span>
                    <span className="font-bold text-white">{Object.keys(results.statistics.by_source_ip).length}</span>
                  </div>
                )}
                {results.statistics?.by_user && (
                  <div className="flex justify-between">
                    <span style={{ color: 'var(--text-3)' }}>Unique Users</span>
                    <span className="font-bold text-white">{Object.keys(results.statistics.by_user).length}</span>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>

        {/* Main: Query Builder & Results */}
        <div className="lg:col-span-3 space-y-6">
          {/* Natural-language hunt */}
          <Card style={{ background: 'rgba(225,29,72,0.05)', border: '1px solid rgba(225,29,72,0.2)' }}>
            <SectionHead title="Ask in Plain English" icon={Wand2} />
            <p className="text-xs mb-3" style={{ color: 'var(--text-3)' }}>
              Describe the threat in your own words — AI translates it to a safe, validated query.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={nlText}
                onChange={e => setNlText(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleNlHunt()}
                placeholder='e.g. "failed logins followed by success from the same IP at night"'
                className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
              />
              <button
                onClick={handleNlHunt}
                disabled={nlLoading}
                className="px-4 py-2.5 rounded-lg font-bold text-white transition-all inline-flex items-center gap-2 disabled:opacity-60"
                style={{ background: 'linear-gradient(135deg,#9f1239,#e11d48)' }}
              >
                {nlLoading ? <Loader2 size={16} className="animate-spin" /> : <Sparkles size={16} />}
                Translate
              </button>
            </div>
            {interpretation && (
              <p className="text-xs mt-3 px-3 py-2 rounded-lg" style={{ background: 'var(--surface-2)', color: 'var(--text-2)' }}>
                <span className="font-bold" style={{ color: 'var(--accent)' }}>Interpreted as: </span>{interpretation}
              </p>
            )}
          </Card>

          {/* Query Builder */}
          <Card>
            <SectionHead title="Hunt Query Builder" icon={SlidersHorizontal} />

            <div className="space-y-4">
              {/* Filters */}
              <div>
                <label className="text-xs font-bold uppercase tracking-widest mb-3 block" style={{ color: 'var(--text-3)' }}>
                  Filters ({filters.length})
                </label>
                <div className="space-y-2">
                  {filters.map((f, idx) => (
                    <div key={idx} className="flex gap-2 items-end">
                      <select
                        value={f.field}
                        onChange={(e) => handleFilterChange(idx, 'field', e.target.value)}
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      >
                        <option value="">— Select Field —</option>
                        {fieldOptions.map(opt => (
                          <option key={opt} value={opt}>{opt}</option>
                        ))}
                      </select>
                      <select
                        value={f.operator}
                        onChange={(e) => handleFilterChange(idx, 'operator', e.target.value)}
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      >
                        <option value="">— Operator —</option>
                        {operatorOptions.map(op => (
                          <option key={op} value={op}>{op}</option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={f.value}
                        onChange={(e) => handleFilterChange(idx, 'value', e.target.value)}
                        placeholder="Value"
                        className="flex-1 px-3 py-2.5 text-sm rounded-lg border"
                        style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', color: 'var(--text-1)' }}
                      />
                      {filters.length > 1 && (
                        <button
                          onClick={() => handleRemoveFilter(idx)}
                          className="px-3 py-2.5 rounded-lg text-sm font-bold transition-all"
                          style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>

                <button
                  onClick={handleAddFilter}
                  className="mt-2 text-sm font-semibold px-4 py-2 rounded-lg transition-all inline-flex items-center gap-1.5"
                  style={{ background: 'rgba(99,102,241,0.15)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)' }}
                >
                  <Plus size={14} /> Add Filter
                </button>
              </div>

              {error && (
                <div className="p-3 rounded-lg text-sm" style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' }}>
                  {error}
                </div>
              )}

              {/* Execute Button */}
              <button
                onClick={handleExecuteHunt}
                disabled={loading}
                className="w-full py-3 rounded-lg font-bold text-white transition-all"
                style={{
                  background: loading ? 'rgba(225,29,72,0.3)' : 'linear-gradient(135deg,#9f1239,#e11d48)',
                  opacity: loading ? 0.6 : 1,
                }}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 size={16} className="animate-spin" />
                    Executing Hunt...
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <Crosshair size={16} /> Execute Hunt
                  </span>
                )}
              </button>
            </div>
          </Card>

          {/* Results */}
          {results && (
            <Card>
              <SectionHead title="Hunt Results" icon={BarChart3} />

              {/* Suggested Alerts */}
              {results.suggested_alerts && results.suggested_alerts.length > 0 && (
                <div className="mb-6 space-y-3">
                  <p className="text-sm font-bold flex items-center gap-1.5" style={{ color: 'var(--text-3)' }}>
                    <Lightbulb size={15} style={{ color: 'var(--accent)' }} /> AI Suggested Alerts
                  </p>
                  {results.suggested_alerts.map((alert, idx) => (
                    <div key={idx} className="p-4 rounded-xl border" style={{ background: 'rgba(99,102,241,0.08)', borderColor: 'rgba(99,102,241,0.2)' }}>
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1">
                          <div className="font-semibold text-white text-sm">{alert.rule_name}</div>
                          <div className="text-xs mt-1" style={{ color: 'var(--text-3)' }}>{alert.description}</div>
                        </div>
                        <button
                          onClick={() => handleSaveAlert(alert)}
                          className="px-3 py-1.5 rounded-lg text-xs font-bold whitespace-nowrap transition-all"
                          style={{ background: 'rgba(225,29,72,0.15)', color: '#f87171', border: '1px solid rgba(225,29,72,0.3)' }}
                        >
                          Save Alert
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Results Table */}
              {results.matching_rows && results.matching_rows.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        {Object.keys(results.matching_rows[0]).slice(0, 6).map(k => (
                          <th key={k} className="text-left py-2 px-3 font-bold" style={{ color: 'var(--text-3)' }}>
                            {k}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {results.matching_rows.slice(0, 15).map((row, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid var(--border)', background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
                          {Object.entries(row)
                            .slice(0, 6)
                            .map(([k, v]) => (
                              <td key={k} className="py-2 px-3 truncate" style={{ color: 'var(--text-2)' }}>
                                {String(v).substring(0, 25)}
                              </td>
                            ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {results.matching_rows.length > 15 && (
                    <p className="text-xs mt-3" style={{ color: 'var(--text-4)' }}>
                      Showing 15 of {results.row_count} rows
                    </p>
                  )}
                </div>
              )}

              {results.matching_rows?.length === 0 && (
                <div className="text-center py-8" style={{ color: 'var(--text-3)' }}>
                  <p className="text-sm">No matching rows found for this hunt</p>
                </div>
              )}
            </Card>
          )}

          {!results && !loading && (
            <Card style={{ background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.15)' }}>
              <div className="text-center py-8 sm:py-12 px-4">
                <Crosshair size={28} className="mx-auto mb-3" style={{ color: 'var(--accent)' }} />
                <p className="text-base sm:text-lg font-semibold text-white mb-2">Ready to hunt</p>
                <p className="text-xs sm:text-sm max-w-sm mx-auto" style={{ color: 'var(--text-3)' }}>
                  Ask in plain English, pick a template, or build a custom query to search for threats
                </p>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
