/**
 * api/client.js
 * =============
 * Central Axios instance for all backend calls.
 * Vite's dev-server proxy rewrites /api/* → http://localhost:8000/*
 * so in dev we never hit CORS issues.
 */
import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '/api',
  timeout: 30_000,
})

// ─── Ingest ──────────────────────────────────────────────────────────────────
/** Upload a log file. Returns { session_id, alerts, event_count, ... } */
export const ingestFile = (file, onProgress) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/ingest', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: onProgress,
  })
}

/** Create a real backend session from a synthetic multi-stage attack. */
export const ingestDemo = () => api.post('/ingest/demo')

// ─── Session ─────────────────────────────────────────────────────────────────
export const getSession   = (sessionId) => api.get(`/session/${sessionId}`)
export const deleteSession = (sessionId) => api.delete(`/session/${sessionId}`)

// ─── Alerts ──────────────────────────────────────────────────────────────────
export const listAlerts = (sessionId)            => api.get(`/alerts/${sessionId}`)
export const getAlert   = (sessionId, alertId)   => api.get(`/alerts/${sessionId}/${alertId}`)

// ─── Investigation ───────────────────────────────────────────────────────────
export const investigate = (sessionId, alertId)  => api.get(`/investigate/${sessionId}/${alertId}`)

// ─── Verdict ─────────────────────────────────────────────────────────────────
export const submitVerdict  = (payload)     => api.post('/verdict', payload)
export const listVerdicts   = (sessionId)   => api.get(`/verdict/${sessionId}`)

// ─── Threat intel ────────────────────────────────────────────────────────────
export const threatIntel = (sessionId, ip) => api.get(`/threatintel/${sessionId}/${ip}`)

// ─── Playbook ────────────────────────────────────────────────────────────────
export const getPlaybook = (ruleId) => api.get(`/playbook/${ruleId}`)

// ─── Report ──────────────────────────────────────────────────────────────────
/** Returns a blob URL the browser can use for download. */
export const downloadReport = async (sessionId, analyst = 'L2 Analyst') => {
  const resp = await api.get(`/report/${sessionId}`, {
    params: { analyst },
    responseType: 'blob',
  })
  return URL.createObjectURL(resp.data)
}

// Feature 4 - Feedback (FP Learning)
export const getFeedback = (sessionId) => api.get(`/feedback/${sessionId}`)

// Feature 5 - Custom Rules (DSL)
export const listCustomRules = (sessionId) => api.get(`/custom-rules/${sessionId}`)
export const createCustomRule = (sessionId, ruleDef) => api.post(`/custom-rules/${sessionId}`, ruleDef)
export const deleteCustomRule = (sessionId, ruleId) => api.delete(`/custom-rules/${sessionId}/${ruleId}`)

// Feature 7 - Assets (Criticality Context)
export const uploadAssets = (sessionId, file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post(`/assets/${sessionId}`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}
export const getAssets = (sessionId) => api.get(`/assets/${sessionId}`)
export const enrichAssets = (sessionId) => api.post(`/enrich-assets/${sessionId}`)

// Feature 8 - Hunt (Threat Hunting)
export const getHuntTemplates = (sessionId) => api.get(`/hunt/${sessionId}/templates`)
export const executeHunt = (sessionId, query) => api.post(`/hunt/${sessionId}`, query)
export const saveHuntAlert = (sessionId, alertDict) => api.post(`/hunt/${sessionId}/save-alert`, alertDict)

// AI Investigation Agent
export const agentInvestigate = (sessionId, alertId, deep = true) =>
  api.post(`/agent/${sessionId}/investigate/${alertId}`, null, { params: { deep } })
export const getChainNarrative = (sessionId) => api.get(`/agent/${sessionId}/chain-narrative`)
export const getVerdictAssist = (sessionId, alertId) => api.get(`/agent/${sessionId}/verdict-assist/${alertId}`)

// Natural-language Hunt
export const nlHunt = (sessionId, query) => api.post(`/hunt/${sessionId}/nl`, { query })

// Feature 9 - Graph (Entity Visualization)
export const getGraph = (sessionId) => api.get(`/graph/${sessionId}`)
export const getAlertGraph = (sessionId, alertId) => api.get(`/graph/${sessionId}/alert/${alertId}`)
