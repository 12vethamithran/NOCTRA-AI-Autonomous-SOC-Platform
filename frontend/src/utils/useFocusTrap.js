/**
 * useFocusTrap(active, ref)
 * --------------------------
 * Confines Tab/Shift+Tab inside the element pointed to by `ref` while
 * `active` is true. Stores the previously focused element and restores it
 * on close — standard ARIA dialog pattern.
 *
 * Used by CommandPalette and the alert DetailDrawer so keyboard users
 * don't tab behind a modal overlay.
 */
import { useEffect } from 'react'

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'textarea:not([disabled])',
  'input:not([disabled]):not([type="hidden"])', 'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

export default function useFocusTrap(active, ref) {
  useEffect(() => {
    if (!active || !ref?.current) return undefined
    const node = ref.current
    const previouslyFocused = document.activeElement

    // Move focus into the container on open.
    const focusables = node.querySelectorAll(FOCUSABLE)
    const first = focusables[0]
    if (first instanceof HTMLElement) first.focus()
    else node.setAttribute('tabindex', '-1'), node.focus()

    const onKey = (e) => {
      if (e.key !== 'Tab') return
      const list = Array.from(node.querySelectorAll(FOCUSABLE))
      if (list.length === 0) {
        e.preventDefault()
        return
      }
      const idx = list.indexOf(document.activeElement)
      const last = list.length - 1
      if (e.shiftKey && (idx <= 0)) {
        e.preventDefault()
        list[last].focus()
      } else if (!e.shiftKey && (idx === last || idx === -1)) {
        e.preventDefault()
        list[0].focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (previouslyFocused instanceof HTMLElement) {
        previouslyFocused.focus()
      }
    }
  }, [active, ref])
}
