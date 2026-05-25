/**
 * <Kbd>⌘</Kbd> <Kbd>K</Kbd>
 *
 * Tiny key cap. Wraps the .ent-kbd token. Mostly used in CommandPalette,
 * shortcuts modal, and footer hints.
 */
export default function Kbd({ children, className = '' }) {
  return <kbd className={`ent-kbd ${className}`}>{children}</kbd>
}
