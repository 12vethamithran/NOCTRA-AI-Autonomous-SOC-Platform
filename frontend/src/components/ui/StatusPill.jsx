/**
 * <StatusPill tone="success|warning|danger|info|accent|neutral" dot label="Engine online" />
 *
 * Replaces the 6+ hand-rolled colored pills (engine health, session badge,
 * MITRE tag, rule status, AI recommendation). Tone maps to a semantic color
 * from the design tokens so a tone swap is one prop, not a colour rewrite.
 */
import { memo } from 'react'

const TONE_CLASS = {
  success: 'ent-pill-success',
  warning: 'ent-pill-warning',
  danger:  'ent-pill-danger',
  info:    'ent-pill-info',
  accent:  'ent-pill-accent',
  neutral: 'ent-pill-neutral',
}

function StatusPill({
  tone = 'neutral',
  dot = false,
  pulse = false,
  icon: Icon,
  children,
  label,
  className = '',
  ...rest
}) {
  return (
    <span
      className={`ent-pill ${TONE_CLASS[tone] || TONE_CLASS.neutral} ${className}`}
      role="status"
      {...rest}
    >
      {dot && (
        <span
          className={`ent-pill-dot ${pulse ? 'accent-pulse' : ''}`}
          aria-hidden="true"
        />
      )}
      {Icon && <Icon size={11} aria-hidden="true" />}
      <span>{children ?? label}</span>
    </span>
  )
}

export default memo(StatusPill)
