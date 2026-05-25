/**
 * <SectionHeader eyebrow="OVERVIEW" title="Active session" hint="…" right={<…/>} />
 *
 * The standard page / section heading block. Replaces the ad-hoc
 *   <div><p class="…">EYEBROW</p><h1 class="…">Title</h1></div>
 * patterns scattered across every page. Right slot for actions/CTAs.
 */
export default function SectionHeader({
  eyebrow,
  title,
  hint,
  right,
  className = '',
  level = 1,
}) {
  const Tag = `h${Math.min(Math.max(level, 1), 6)}`
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
