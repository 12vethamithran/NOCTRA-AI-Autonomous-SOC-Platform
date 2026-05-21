import { useEffect, useRef } from 'react'

/* ─────────────────────────────────────────────────────────────────────────────
   Noctra AI Threat-Network Background
   • 55 nodes with z-depth simulation
   • Connection lines (normal = blue-grey, alert = crimson)
   • Animated data packets traveling between nodes
   • Critical nodes: pulsing red radial glow + orbiting ring
   • Horizontal radar scan line
   • Perspective grid that recedes to vanishing point
   • Floating hex shapes (large, very transparent)
   • Mouse repulsion field (cursor pushes nearby nodes)
   • All canvas drawing — zero DOM nodes after mount
───────────────────────────────────────────────────────────────────────────── */

const NODE_COUNT      = 58
const CONNECT_DIST    = 165
const MOUSE_REPEL_R   = 145
const PACKET_INTERVAL = 50   // frames between packet spawns
const SCAN_SPEED      = 0.35

function rand(min, max) { return Math.random() * (max - min) + min }
function randInt(min, max) { return Math.floor(rand(min, max + 1)) }
function randIp() { return `${randInt(1,254)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(0,255)}` }

function makeNode(W, H) {
  const type = Math.random() < 0.06 ? 'critical'
             : Math.random() < 0.14 ? 'alert'
             : 'normal'
  return {
    x:     rand(0, W),
    y:     rand(0, H),
    z:     rand(0.25, 1),          // depth — 1 = close, 0 = far
    vx:    rand(-0.22, 0.22),
    vy:    rand(-0.22, 0.22),
    type,
    phase: rand(0, Math.PI * 2),
    size:  rand(1.4, 3.0),
    ip:    type !== 'normal' ? randIp() : null,
    ring:  0,                      // orbiting ring angle
  }
}

function makeHex(W, H) {
  return {
    x:     rand(0, W),
    y:     rand(0, H),
    r:     rand(40, 110),
    vx:    rand(-0.06, 0.06),
    vy:    rand(-0.06, 0.06),
    rot:   rand(0, Math.PI),
    vrot:  rand(-0.0005, 0.0005),
    alpha: rand(0.012, 0.04),
  }
}

export default function BackgroundCanvas() {
  const canvasRef = useRef(null)
  const mouseRef  = useRef({ x: null, y: null })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    let animId
    let frame   = 0
    let scanY   = 0
    let nodes   = []
    let hexes   = []
    let packets = []

    /* ── Initialise ──────────────────────────────────────────────────────── */
    const init = () => {
      canvas.width  = window.innerWidth
      canvas.height = window.innerHeight
      const W = canvas.width, H = canvas.height
      nodes   = Array.from({ length: NODE_COUNT }, () => makeNode(W, H))
      hexes   = Array.from({ length: 9 },         () => makeHex(W, H))
      packets = []
      scanY   = 0
    }

    /* ── Perspective grid ────────────────────────────────────────────────── */
    const drawGrid = () => {
      const W = canvas.width, H = canvas.height
      const vx = W / 2, vy = H * 0.45        // vanishing point
      const lines = 18
      const opacity = 0.028

      ctx.strokeStyle = `rgba(225,29,72,${opacity})`
      ctx.lineWidth = 0.5

      // Horizontal lines (receding)
      for (let i = 0; i <= lines; i++) {
        const t  = i / lines
        const y  = vy + (H - vy) * t
        const hw = (W * 0.5) * t             // half-width at this depth
        ctx.beginPath()
        ctx.moveTo(vx - hw, y)
        ctx.lineTo(vx + hw, y)
        ctx.stroke()
      }

      // Vertical fan lines
      const fans = 14
      for (let i = 0; i <= fans; i++) {
        const t  = i / fans
        const bx = t * W                     // bottom x
        ctx.beginPath()
        ctx.moveTo(vx, vy)
        ctx.lineTo(bx, H)
        ctx.stroke()
      }
    }

    /* ── Hex shape ───────────────────────────────────────────────────────── */
    const drawHex = (hx, hy, r, rot, alpha) => {
      ctx.save()
      ctx.translate(hx, hy)
      ctx.rotate(rot)
      ctx.beginPath()
      for (let k = 0; k < 6; k++) {
        const a = (k / 6) * Math.PI * 2
        const px = r * Math.cos(a), py = r * Math.sin(a)
        k === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py)
      }
      ctx.closePath()
      ctx.strokeStyle = `rgba(225,29,72,${alpha})`
      ctx.lineWidth = 0.8
      ctx.stroke()
      // inner ring
      ctx.beginPath()
      for (let k = 0; k < 6; k++) {
        const a = (k / 6) * Math.PI * 2
        const px = r * 0.55 * Math.cos(a), py = r * 0.55 * Math.sin(a)
        k === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py)
      }
      ctx.closePath()
      ctx.strokeStyle = `rgba(225,29,72,${alpha * 0.5})`
      ctx.stroke()
      ctx.restore()
    }

    /* ── Main animation loop ─────────────────────────────────────────────── */
    const animate = () => {
      animId = requestAnimationFrame(animate)
      frame++

      const W = canvas.width, H = canvas.height
      ctx.clearRect(0, 0, W, H)

      /* -- Perspective grid -- */
      drawGrid()

      /* -- Floating hexagons -- */
      hexes.forEach(h => {
        h.x   += h.vx; h.y += h.vy; h.rot += h.vrot
        if (h.x < -h.r)     h.x = W + h.r
        if (h.x > W + h.r)  h.x = -h.r
        if (h.y < -h.r)     h.y = H + h.r
        if (h.y > H + h.r)  h.y = -h.r
        drawHex(h.x, h.y, h.r, h.rot, h.alpha)
      })

      /* -- Update nodes -- */
      const mouse = mouseRef.current
      nodes.forEach(n => {
        n.phase += 0.018
        n.ring  += 0.012

        if (mouse.x !== null) {
          const dx = n.x - mouse.x, dy = n.y - mouse.y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < MOUSE_REPEL_R && dist > 0) {
            const f = ((MOUSE_REPEL_R - dist) / MOUSE_REPEL_R) * 0.45
            n.vx += (dx / dist) * f
            n.vy += (dy / dist) * f
          }
        }

        n.vx *= 0.97; n.vy *= 0.97
        n.x += n.vx;  n.y += n.vy

        if (n.x < -20) n.x = W + 20
        if (n.x > W + 20) n.x = -20
        if (n.y < -20) n.y = H + 20
        if (n.y > H + 20) n.y = -20
      })

      /* -- Spawn packets -- */
      if (frame % PACKET_INTERVAL === 0) {
        const src = nodes[Math.floor(Math.random() * nodes.length)]
        const candidates = nodes.filter(n => {
          const d = Math.hypot(n.x - src.x, n.y - src.y)
          return d > 30 && d < CONNECT_DIST + 20
        })
        if (candidates.length) {
          const dst = candidates[Math.floor(Math.random() * candidates.length)]
          packets.push({
            x0: src.x, y0: src.y, x1: dst.x, y1: dst.y,
            p: 0,
            spd: rand(0.01, 0.022),
            isAlert: src.type !== 'normal' || dst.type !== 'normal',
          })
        }
      }

      /* -- Draw connection lines -- */
      ctx.save()
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j]
          const dist = Math.hypot(a.x - b.x, a.y - b.y)
          if (dist > CONNECT_DIST) continue
          const fade   = (1 - dist / CONNECT_DIST)
          const depth  = Math.min(a.z, b.z)
          const alpha  = fade * depth * 0.18
          const isAlt  = a.type !== 'normal' || b.type !== 'normal'
          ctx.strokeStyle = isAlt
            ? `rgba(225,29,72,${alpha * 1.6})`
            : `rgba(96,140,200,${alpha})`
          ctx.lineWidth = isAlt ? 0.7 : 0.45
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
        }
      }
      ctx.restore()

      /* -- Draw nodes -- */
      nodes.forEach(n => {
        const pulse  = Math.sin(n.phase)
        const r      = n.size * (0.6 + n.z * 0.7)

        if (n.type === 'critical') {
          // Outer radial glow
          const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 9)
          grd.addColorStop(0, `rgba(225,29,72,${0.22 + pulse * 0.07})`)
          grd.addColorStop(0.5, `rgba(225,29,72,0.05)`)
          grd.addColorStop(1, 'transparent')
          ctx.fillStyle = grd
          ctx.beginPath()
          ctx.arc(n.x, n.y, r * 9, 0, Math.PI * 2)
          ctx.fill()

          // Orbiting ring
          const orbitR = r * (3.5 + pulse * 0.4)
          const ox = n.x + orbitR * Math.cos(n.ring)
          const oy = n.y + orbitR * Math.sin(n.ring)
          ctx.strokeStyle = `rgba(239,68,68,${0.55 + pulse * 0.2})`
          ctx.lineWidth = 0.8
          ctx.beginPath()
          ctx.arc(n.x, n.y, orbitR, 0, Math.PI * 2)
          ctx.stroke()
          // Orbiting dot
          ctx.fillStyle = 'rgba(239,68,68,0.9)'
          ctx.beginPath()
          ctx.arc(ox, oy, 1.5, 0, Math.PI * 2)
          ctx.fill()

          // Expanding pulse ring
          const pr = r * (2 + ((frame * 0.02 + n.phase) % (Math.PI * 2)) / (Math.PI * 2) * 6)
          const pa = Math.max(0, 0.4 - pr / (r * 8))
          ctx.strokeStyle = `rgba(239,68,68,${pa})`
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.arc(n.x, n.y, pr, 0, Math.PI * 2)
          ctx.stroke()

          ctx.fillStyle = `rgba(239,68,68,${0.85 + pulse * 0.15})`

        } else if (n.type === 'alert') {
          // Soft glow
          const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 5)
          grd.addColorStop(0, `rgba(251,146,60,${0.18 + pulse * 0.05})`)
          grd.addColorStop(1, 'transparent')
          ctx.fillStyle = grd
          ctx.beginPath()
          ctx.arc(n.x, n.y, r * 5, 0, Math.PI * 2)
          ctx.fill()
          ctx.fillStyle = `rgba(251,146,60,${0.65 + pulse * 0.15})`

        } else {
          const bright = 55 + n.z * 75
          ctx.fillStyle = `rgba(${bright},${bright + 25},${bright + 75},${0.25 + n.z * 0.45})`
        }

        // Core node
        ctx.beginPath()
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2)
        ctx.fill()

        // Hex outline on large nodes
        if (n.z > 0.65) {
          ctx.strokeStyle = n.type === 'critical'
            ? `rgba(239,68,68,${0.25 + pulse * 0.1})`
            : n.type === 'alert'
              ? 'rgba(251,146,60,0.2)'
              : `rgba(100,150,220,${0.12 * n.z})`
          ctx.lineWidth = 0.5
          const hs = r * 2.3
          ctx.beginPath()
          for (let k = 0; k < 6; k++) {
            const ang = (k / 6) * Math.PI * 2
            const hpx = n.x + hs * Math.cos(ang)
            const hpy = n.y + hs * Math.sin(ang)
            k === 0 ? ctx.moveTo(hpx, hpy) : ctx.lineTo(hpx, hpy)
          }
          ctx.closePath()
          ctx.stroke()
        }

        // IP label for threat nodes
        if (n.ip && n.z > 0.55) {
          ctx.fillStyle = n.type === 'critical'
            ? `rgba(239,68,68,${0.45 * n.z})`
            : `rgba(251,146,60,${0.35 * n.z})`
          ctx.font = `${Math.round(6.5 * n.z)}px ui-monospace, monospace`
          ctx.fillText(n.ip, n.x + r + 5, n.y + 3)
        }
      })

      /* -- Draw & update packets -- */
      packets = packets.filter(pk => {
        pk.p += pk.spd
        if (pk.p >= 1) return false
        const x = pk.x0 + (pk.x1 - pk.x0) * pk.p
        const y = pk.y0 + (pk.y1 - pk.y0) * pk.p
        const tailLen = 6

        // Trail
        for (let t = 0; t < tailLen; t++) {
          const tp  = Math.max(0, pk.p - t * 0.012)
          const tx  = pk.x0 + (pk.x1 - pk.x0) * tp
          const ty  = pk.y0 + (pk.y1 - pk.y0) * tp
          const ta  = (1 - t / tailLen) * (pk.isAlert ? 0.7 : 0.5)
          ctx.fillStyle = pk.isAlert ? `rgba(225,29,72,${ta})` : `rgba(56,189,248,${ta})`
          ctx.beginPath()
          ctx.arc(tx, ty, pk.isAlert ? 1.8 : 1.4, 0, Math.PI * 2)
          ctx.fill()
        }

        // Head glow
        const grd = ctx.createRadialGradient(x, y, 0, x, y, 7)
        grd.addColorStop(0, pk.isAlert ? 'rgba(225,29,72,0.5)' : 'rgba(56,189,248,0.35)')
        grd.addColorStop(1, 'transparent')
        ctx.fillStyle = grd
        ctx.beginPath()
        ctx.arc(x, y, 7, 0, Math.PI * 2)
        ctx.fill()

        return true
      })

      /* -- Scan line -- */
      scanY = (scanY + SCAN_SPEED) % H
      ctx.fillStyle = 'rgba(225,29,72,0.035)'
      ctx.fillRect(0, scanY - 1, W, 3)
      ctx.fillStyle = 'rgba(225,29,72,0.010)'
      ctx.fillRect(0, scanY - 12, W, 12)
      // Glow on scan line
      const sg = ctx.createLinearGradient(0, scanY - 2, 0, scanY + 2)
      sg.addColorStop(0,   'transparent')
      sg.addColorStop(0.5, 'rgba(225,29,72,0.06)')
      sg.addColorStop(1,   'transparent')
      ctx.fillStyle = sg
      ctx.fillRect(0, scanY - 2, W, 4)
    }

    init()
    animate()

    const onResize     = () => init()
    const onMouseMove  = e => { mouseRef.current = { x: e.clientX, y: e.clientY } }
    const onMouseLeave = () => { mouseRef.current = { x: null,     y: null      } }

    window.addEventListener('resize',      onResize)
    window.addEventListener('mousemove',   onMouseMove)
    window.addEventListener('mouseleave',  onMouseLeave)

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize',     onResize)
      window.removeEventListener('mousemove',  onMouseMove)
      window.removeEventListener('mouseleave', onMouseLeave)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position:      'fixed',
        top:           0,
        left:          0,
        width:         '100vw',
        height:        '100vh',
        pointerEvents: 'none',
        zIndex:        0,
        opacity:       1,
      }}
    />
  )
}
