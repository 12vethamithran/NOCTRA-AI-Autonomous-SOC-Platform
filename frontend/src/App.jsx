/**
 * App.jsx
 * =======
 * Root router. Session context is shared via React context so every page
 * can read session_id without prop-drilling.
 */
import { createContext, useContext, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout  from './components/Layout'
import Landing from './pages/Landing'
import Upload  from './pages/Upload'
import Triage  from './pages/Triage'
import Investigation from './pages/Investigation'
import Dashboard from './pages/Dashboard'
import HuntPage from './pages/HuntPage'
import RuleBuilderPage from './pages/RuleBuilderPage'

// ── Session context ──────────────────────────────────────────────────────────
export const SessionCtx = createContext(null)
export const useSession = () => useContext(SessionCtx)

export default function App() {
  const [session, setSession] = useState(null)
  // session shape: { session_id, event_count, parsed_format, alerts: [...] }

  return (
    <SessionCtx.Provider value={{ session, setSession }}>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/"            element={<Landing />} />
          <Route path="/upload"      element={<Upload />} />
          <Route path="/triage"      element={session ? <Triage />      : <Navigate to="/upload" />} />
          <Route path="/investigate/:alertId" element={session ? <Investigation /> : <Navigate to="/upload" />} />
          <Route path="/hunt"        element={session ? <HuntPage />    : <Navigate to="/upload" />} />
          <Route path="/rules"       element={session ? <RuleBuilderPage /> : <Navigate to="/upload" />} />
          <Route path="/dashboard"   element={session ? <Dashboard />   : <Navigate to="/upload" />} />
        </Route>
      </Routes>
    </SessionCtx.Provider>
  )
}
