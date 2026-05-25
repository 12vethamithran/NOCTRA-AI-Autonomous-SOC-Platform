/**
 * <SeverityBadge sev="HIGH" />
 *
 * Single source of truth for alert severity styling.
 * Composes the global `.sev-chip-*` tokens defined in index.css so a theme
 * change touches one CSS block, not 30 inline color strings. Memoized — these
 * render thousands of times in the Triage table.
 */
import { memo } from 'react'

const CLASS = {
  CRITICAL: 'sev-chip sev-chip-critical',
  HIGH:     'sev-chip sev-chip-high',
  MEDIUM:   'sev-chip sev-chip-medium',
  LOW:      'sev-chip sev-chip-low',
}

function SeverityBadge({ sev = 'LOW', label }) {
  const key = String(sev).toUpperCase()
  return (
    <span
      className={CLASS[key] || CLASS.LOW}
      role="status"
      aria-label={`Severity ${label || key}`}
    >
      {label || key}
    </span>
  )
}

export default memo(SeverityBadge)
