/**
 * <EmptyState icon={Inbox} title="No alerts yet" hint="Upload a log file…" action={<Button …/>} />
 *
 * Consistent empty-state across every page. Replaces ~7 hand-rolled empty
 * blocks (Triage, Hunt, Investigation, Dashboard…) that drifted apart over
 * time. Optional action slot for a primary CTA so empty isn't a dead-end.
 */
export default function EmptyState({ icon: Icon, title, hint, action, className = '' }) {
  return (
    <div
      className={`flex flex-col items-center justify-center text-center px-6 py-12 rounded-xl ${className}`}
      style={{
        background: 'var(--surface)',
        border: '1px dashed var(--border-2)',
      }}
      role="status"
    >
      {Icon && (
        <div
          className="w-12 h-12 mb-4 rounded-full flex items-center justify-center"
          style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}
          aria-hidden="true"
        >
          <Icon size={22} />
        </div>
      )}
      {title && (
        <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--text-1)' }}>
          {title}
        </h3>
      )}
      {hint && (
        <p className="text-sm max-w-md" style={{ color: 'var(--text-3)' }}>
          {hint}
        </p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
