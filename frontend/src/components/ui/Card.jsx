/**
 * <Card variant="default|elevated|muted|interactive" padding="md|lg|none">
 *
 * Wraps the .ent-card token from index.css so pages stop hand-rolling
 *   <div style={{ background: 'var(--surface)', border: '1px solid …' }}>
 * blocks. Enterprise default: subtle border, hairline elevation.
 */
const PAD = {
  none: '',
  sm: 'p-3',
  md: 'p-4',
  lg: 'p-5',
  xl: 'p-6',
}

export default function Card({
  variant = 'default',
  padding = 'md',
  as: Tag = 'div',
  className = '',
  children,
  ...rest
}) {
  const cls = [
    'ent-card',
    variant === 'elevated' && 'ent-card-elevated',
    variant === 'muted' && 'ent-card-muted',
    variant === 'interactive' && 'ent-card-elevated ent-card-interactive',
    PAD[padding],
    className,
  ].filter(Boolean).join(' ')
  return <Tag className={cls} {...rest}>{children}</Tag>
}
