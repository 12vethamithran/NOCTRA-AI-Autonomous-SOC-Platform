/**
 * useCountUp(target, { duration, decimals })
 * -------------------------------------------
 * Animates a numeric value from 0 → target when the returned ref enters the
 * viewport. Uses IntersectionObserver so off-screen metrics don't waste a
 * frame loop, and a cubic ease-out so the number feels weighted, not robotic.
 *
 *   const { ref, value } = useCountUp(42, { duration: 700 })
 *   <span ref={ref}>{value}</span>
 *
 * Returns `value` as a number you can format yourself (toLocaleString,
 * `<` prefix for "less than" thresholds, etc).
 */
import { useEffect, useRef, useState } from 'react'

export default function useCountUp(target, { duration = 700, decimals = 0 } = {}) {
  const ref = useRef(null)
  const [value, setValue] = useState(0)
  const startedRef = useRef(false)

  useEffect(() => {
    const node = ref.current
    if (!node) return
    if (startedRef.current) {
      // Re-run when target changes after first animation.
      runAnim()
      return
    }
    const io = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !startedRef.current) {
        startedRef.current = true
        runAnim()
        io.disconnect()
      }
    }, { threshold: 0.4 })
    io.observe(node)
    return () => io.disconnect()

    function runAnim() {
      const start = performance.now()
      const from = 0
      const to = Number.isFinite(target) ? target : 0
      let raf
      const tick = (now) => {
        const p = Math.min(1, (now - start) / duration)
        const eased = 1 - Math.pow(1 - p, 3)
        const v = from + (to - from) * eased
        setValue(decimals > 0 ? Number(v.toFixed(decimals)) : Math.round(v))
        if (p < 1) raf = requestAnimationFrame(tick)
      }
      raf = requestAnimationFrame(tick)
    }
  }, [target, duration, decimals])

  return { ref, value }
}
