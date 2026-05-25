/**
 * App.jsx
 * =======
 * Root router. Session context is shared via React context so every page
 * can read session_id without prop-drilling.
 *
 * Routes are lazy-loaded so the first paint only ships the Landing page
 * plus the shell. Heavy pages (Dashboard with recharts, Investigation with
 * force-graph) download on demand.
 */
import { createContext, useContext, useState, lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import { SkeletonBlock } from './components/ui/Skeleton'

const Landing         = lazy(() => import('./pages/Landing'))
const Upload          = lazy(() => import('./pages/Upload'))
const Triage          = lazy(() => import('./pages/Triage'))
const Investigation   = lazy(() => import('./pages/Investigation'))
const Dashboard       = lazy(() => import('./pages/Dashboard'))
const HuntPage        = lazy(() => import('./pages/HuntPage'))
const RuleBuilderPage = lazy(() => import('./pages/RuleBuilderPage'))

// ── Session context ──────────────────────────────────────────────────────────
export const SessionCtx = createContext(null)
export const useSession = () => useContext(SessionCtx)

// Lightweight route-level fallback. Keeps layout intact while the lazy
// chunk arrives so the user never sees a flash of white.
function RouteFallback() {
  return (
    <div className="p-8 space-y-4" aria-busy="true">
      <SkeletonBlock h="32px" w="40%" />
      <SkeletonBlock h="180px" />
      <SkeletonBlock h="120px" />
    </div>
  )
}

export default function App() {
  const [session, setSession] = useState(null)
  // session shape: { session_id, event_count, parsed_format, alerts: [...] }

  return (
    <SessionCtx.Provider value={{ session, setSession }}>
      <Suspense fallback={<RouteFallback />}>
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
      </Suspense>
    </SessionCtx.Provider>
  )
}
