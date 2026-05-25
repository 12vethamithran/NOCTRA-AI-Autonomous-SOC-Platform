/**
 * <Skeleton /> primitives — eliminate layout shift while data loads.
 *
 * Uses the global `.skel` shimmer token from index.css. Two shapes:
 *   <SkeletonBlock h="80px" />          — generic shape
 *   <SkeletonKPI />                     — a KPI card placeholder matching real card height
 *
 * Preferred over `<Loader2 className="animate-spin"/>` because the analyst
 * can already see the layout, removing the "did it load?" doubt that
 * spinners create on first paint.
 */
export function SkeletonBlock({ h = '16px', w = '100%', radius = 8, className = '' }) {
  return (
    <div
      className={`skel ${className}`}
      style={{ height: h, width: w, borderRadius: radius }}
      aria-hidden="true"
    />
  )
}

export function SkeletonKPI() {
  return (
    <div
      className="p-4 rounded-xl flex flex-col gap-3"
      style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
      aria-hidden="true"
    >
      <SkeletonBlock h="12px" w="55%" />
      <SkeletonBlock h="28px" w="40%" />
      <SkeletonBlock h="10px" w="70%" />
    </div>
  )
}

export function SkeletonRow({ cols = 6 }) {
  return (
    <tr aria-hidden="true">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-3 py-3">
          <SkeletonBlock h="14px" />
        </td>
      ))}
    </tr>
  )
}
