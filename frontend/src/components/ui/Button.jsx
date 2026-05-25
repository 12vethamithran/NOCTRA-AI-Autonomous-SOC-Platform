/**
 * <Button variant="primary|secondary|ghost|danger" size="sm|md" icon={Icon} loading>…</Button>
 *
 * One button. Three variants. Loading state and icon slot baked in.
 * Replaces ~25 hand-styled buttons across Triage/Investigation/Dashboard
 * that drifted into 4 different shades of red and 3 different paddings.
 *
 * Always sets an aria-label when only an icon is rendered, so screen
 * readers don't announce "button" with no context.
 */
import { Loader2 } from 'lucide-react'

const VARIANTS = {
  primary: {
    background: 'var(--accent)',
    color: '#fff',
    border: '1px solid var(--accent)',
    hover: 'var(--accent-hover)',
  },
  secondary: {
    background: 'var(--surface-3)',
    color: 'var(--text-1)',
    border: '1px solid var(--border-2)',
    hover: 'var(--surface-4)',
  },
  ghost: {
    background: 'transparent',
    color: 'var(--text-2)',
    border: '1px solid transparent',
    hover: 'var(--surface-2)',
  },
  danger: {
    background: 'rgba(239,68,68,0.12)',
    color: '#f87171',
    border: '1px solid rgba(239,68,68,0.30)',
    hover: 'rgba(239,68,68,0.20)',
  },
}

const SIZES = {
  sm: 'text-xs px-2 py-1 rounded-md gap-1',
  md: 'text-sm px-3 py-2 rounded-lg gap-2',
}

export default function Button({
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  loading = false,
  disabled,
  children,
  className = '',
  ariaLabel,
  ...rest
}) {
  const v = VARIANTS[variant] || VARIANTS.secondary
  const isIconOnly = !children && !!Icon
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      aria-label={ariaLabel || (isIconOnly ? 'action' : undefined)}
      className={`inline-flex items-center justify-center font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${SIZES[size]} ${className}`}
      style={{
        background: v.background,
        color: v.color,
        border: v.border,
        ...rest.style,
      }}
      onMouseEnter={(e) => {
        if (disabled || loading) return
        e.currentTarget.style.background = v.hover
        rest.onMouseEnter?.(e)
      }}
      onMouseLeave={(e) => {
        if (disabled || loading) return
        e.currentTarget.style.background = v.background
        rest.onMouseLeave?.(e)
      }}
    >
      {loading ? (
        <Loader2 size={size === 'sm' ? 12 : 14} className="animate-spin" />
      ) : (
        Icon && <Icon size={size === 'sm' ? 12 : 14} />
      )}
      {children}
    </button>
  )
}
