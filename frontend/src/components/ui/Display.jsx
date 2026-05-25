import { useEffect, useRef, useState } from 'react'

/**
 * Display language primitives — bold-typography / scroll-storytelling layer.
 * Pair with the .display / .eyebrow-display / .feature-numbered tokens in
 * index.css.
 */

export function Eyebrow({ children, num, className = '', ...rest }) {
  if (num != null) {
    return (
      <span className={`eyebrow-num ${className}`} {...rest}>{`// ${String(num).padStart(2, '0')}`}</span>
    )
  }
  return <span className={`eyebrow-display ${className}`} {...rest}>{children}</span>
}

/**
 * <DisplayHeading>
 *   White Caps Phrase.{' '}
 *   <DisplayHeading.Accent>Italic Red Phrase.</DisplayHeading.Accent>
 * </DisplayHeading>
 *
 * Or for the two-line muted variant:
 *   <DisplayHeading>
 *     SAME PASSWORD.
 *     <DisplayHeading.Muted>TWO VERY DIFFERENT CONCLUSIONS.</DisplayHeading.Muted>
 *   </DisplayHeading>
 */
export function DisplayHeading({ size = 'md', center = false, wide = false, as: Tag = 'h2', className = '', children, ...rest }) {
  const sizeClass = size === 'sm' ? 'display display-sm' : size === 'lg' ? 'display display-lg' : 'display'
  const mods = [center && 'is-center', wide && 'is-wide'].filter(Boolean).join(' ')
  return <Tag className={`${sizeClass} ${mods} ${className}`} {...rest}>{children}</Tag>
}
DisplayHeading.Accent = function Accent({ children }) {
  return <span className="display-accent">{children}</span>
}
DisplayHeading.Muted = function Muted({ children }) {
  return <span className="display-muted block">{children}</span>
}

/**
 * <NumberedFeature n={1} title="Profile-aware mutation">
 *   Body copy...
 * </NumberedFeature>
 */
export function NumberedFeature({ n, title, children }) {
  return (
    <div className="feature-numbered reveal">
      <Eyebrow num={n} />
      <h3 className="font-bold mt-4" style={{ fontSize: '17px', color: 'var(--text-1)' }}>{title}</h3>
      <p className="text-sm mt-2" style={{ color: 'var(--text-3)', lineHeight: 1.55 }}>{children}</p>
    </div>
  )
}

/**
 * Ghost text-link CTA. Renders a <button> by default, or an <a> if href given.
 */
export function GhostCTA({ children, href, onClick, ...rest }) {
  if (href) {
    return <a href={href} className="cta-ghost" {...rest}>{children} <span aria-hidden>→</span></a>
  }
  return <button onClick={onClick} className="cta-ghost" {...rest}>{children} <span aria-hidden>→</span></button>
}

/**
 * Wraps children in a faint-grid + soft-red-radial backdrop.
 */
export function GridBackdrop({ children, className = '', ...rest }) {
  return <div className={`grid-backdrop ${className}`} {...rest}>{children}</div>
}

/**
 * <Reveal>...</Reveal> — fade+slide on scroll into view. Uses
 * IntersectionObserver; respects prefers-reduced-motion via CSS.
 * Children must accept className passthrough or be wrapped.
 */
export function Reveal({ children, as: Tag = 'div', delay = 0, className = '', ...rest }) {
  const ref = useRef(null)
  const [revealed, setRevealed] = useState(false)
  useEffect(() => {
    const node = ref.current
    if (!node) return
    if (typeof IntersectionObserver === 'undefined') { setRevealed(true); return }
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          if (delay) setTimeout(() => setRevealed(true), delay)
          else setRevealed(true)
          io.disconnect()
        }
      })
    }, { threshold: 0.15, rootMargin: '0px 0px -10% 0px' })
    io.observe(node)
    return () => io.disconnect()
  }, [delay])
  return (
    <Tag ref={ref} className={`reveal ${className}`} data-revealed={revealed || undefined} {...rest}>
      {children}
    </Tag>
  )
}

/**
 * Stat strip — 4 huge numerals + caption, no card chrome, framed by hairlines.
 * <StatStrip items={[{ value: '2.4B', label: 'Records' }, ...]} />
 */
export function StatStrip({ items }) {
  return (
    <div className="stat-strip">
      {items.map((it, i) => (
        <Reveal key={i} delay={i * 80}>
          <div className="stat-strip-value">{it.value}</div>
          <div className="stat-strip-label">{it.label}</div>
        </Reveal>
      ))}
    </div>
  )
}

/**
 * Logo strip — tracked-out caps "partner" names with thin underline.
 * <LogoStrip names={['NORTHWIND', 'AXIOM', ...]} />
 */
export function LogoStrip({ names }) {
  return (
    <div className="logo-strip">
      {names.map(n => <span key={n}>{n}</span>)}
    </div>
  )
}
