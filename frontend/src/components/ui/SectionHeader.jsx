/**
 * <SectionHeader eyebrow="OVERVIEW" title="Active session" hint="…" right={<…/>} />
 *
 * The standard page / section heading block.
 *   variant="default"  — original compact dense-UI header (data pages).
 *   variant="display"  — bold-caps marketing language (eyebrow with dot,
 *                       oversized uppercase title). Use for page tops on
 *                       app pages and for marketing sections.
 *   variant="display-sm" — smaller display heading for in-page sections.
 */
export default function SectionHeader({
  eyebrow,
  title,
  hint,
  right,
  className = '',
  level = 1,
  variant = 'default',
}) {
  const Tag = `h${Math.min(Math.max(level, 1), 6)}`

  if (variant === 'display' || variant === 'display-sm') {
    const titleSizeClass = variant === 'display-sm'
      ? 'display display-sm'
      : 'display display-sm lg:!text-[clamp(48px,6vw,80px)]'
    return (
      <div className={`flex flex-wrap items-end justify-between gap-4 ${className}`}>
        <div className="min-w-0">
          {eyebrow && <span className="eyebrow-display mb-4 inline-flex">{eyebrow}</span>}
          {title && (
            <Tag className={`${titleSizeClass} mt-4`} style={{ color: 'var(--text-1)' }}>
              {typeof title === 'string' ? title : title}
            </Tag>
          )}
          {hint && (
            <p className="text-sm mt-5 max-w-2xl" style={{ color: 'var(--text-3)', lineHeight: 1.6 }}>
              {hint}
            </p>
          )}
        </div>
        {right && <div className="flex items-center gap-2 shrink-0 self-start pt-2">{right}</div>}
      </div>
    )
  }

  return (
    <div className={`flex flex-wrap items-start justify-between gap-4 ${className}`}>
      <div className="min-w-0">
        {eyebrow && <p className="ent-section-eyebrow mb-1.5">{eyebrow}</p>}
        {title && <Tag className="ent-section-title">{title}</Tag>}
        {hint && (
          <p className="text-sm mt-1.5 max-w-2xl" style={{ color: 'var(--text-3)' }}>
            {hint}
          </p>
        )}
      </div>
      {right && <div className="flex items-center gap-2 shrink-0">{right}</div>}
    </div>
  )
}
