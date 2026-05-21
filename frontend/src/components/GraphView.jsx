import React, { useEffect, useRef, useState, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'

// Single project theme: reds for risk/identity, zinc for infrastructure.
const NODE_STYLE = {
  external_ip: { color: '#ff3b5c', ring: 'rgba(255,59,92,0.35)', label: 'External IP' },
  ip:          { color: '#71717a', ring: 'rgba(113,113,122,0.3)', label: 'Internal IP' },
  user:        { color: '#fb7185', ring: 'rgba(251,113,133,0.3)', label: 'User' },
  host:        { color: '#a1a1aa', ring: 'rgba(161,161,170,0.3)', label: 'Host' },
  unknown:     { color: '#52525b', ring: 'rgba(82,82,91,0.3)', label: 'Entity' },
}

const idOf = (x) => (x && typeof x === 'object' ? x.id : x)

function ToolBtn({ onClick, title, active, children }) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="w-7 h-7 flex items-center justify-center rounded-md transition-colors text-xs"
      style={{
        background: active ? 'rgba(225,29,72,0.18)' : 'rgba(0,0,0,0.55)',
        border: `1px solid ${active ? 'rgba(225,29,72,0.5)' : 'var(--border)'}`,
        color: active ? '#fb7185' : 'var(--text-2)',
      }}
    >
      {children}
    </button>
  )
}

export default function GraphView({ nodes = [], edges = [] }) {
  const fgRef = useRef()
  const wrapRef = useRef()
  const hoverRef = useRef(null)
  const selRef = useRef(null)
  const queryRef = useRef('')
  const [width, setWidth] = useState(640)
  const [sel, setSel] = useState(null)
  const [query, setQuery] = useState('')
  const [showLabels, setShowLabels] = useState(true)
  const [fs, setFs] = useState(false)

  // --- Original sizing behaviour (known-good). Do not change. ---
  useEffect(() => {
    if (!wrapRef.current) return
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width))
    ro.observe(wrapRef.current)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (fgRef.current && nodes.length) {
      const t = setTimeout(() => fgRef.current?.zoomToFit(500, 40), 350)
      return () => clearTimeout(t)
    }
  }, [nodes, width])

  useEffect(() => {
    const onFs = () => setFs(Boolean(document.fullscreenElement))
    document.addEventListener('fullscreenchange', onFs)
    return () => document.removeEventListener('fullscreenchange', onFs)
  }, [])

  // Adjacency for neighbour highlighting.
  const adjacency = {}
  edges.forEach((e) => {
    const s = idOf(e.source), t = idOf(e.target)
    ;(adjacency[s] = adjacency[s] || new Set()).add(t)
    ;(adjacency[t] = adjacency[t] || new Set()).add(s)
  })

  // Original data shape (inline, not memoised) — matches the working version.
  const data = {
    nodes: nodes.map((n) => ({ ...n, val: 4 + Math.min(8, (n.event_count || 0) * 1.5) })),
    links: edges.map((e) => ({ ...e, source: e.source, target: e.target, value: e.count || 1 })),
  }

  const litFor = (id) => {
    if (id == null) return null
    const s = new Set([id])
    ;(adjacency[id] || []).forEach((x) => s.add(x))
    return s
  }

  const paintNode = useCallback((node, ctx, scale) => {
    const st = NODE_STYLE[node.type] || NODE_STYLE.unknown
    const r = node.val
    const finite = Number.isFinite(node.x) && Number.isFinite(node.y)
    const focusId = selRef.current?.id ?? hoverRef.current?.id ?? null
    const lit = litFor(focusId)
    const dim = lit && !lit.has(node.id)
    const q = queryRef.current
    const isHit = q && node.label?.toLowerCase().includes(q)
    ctx.globalAlpha = dim ? 0.15 : 1

    // Glow — only when coords are finite (gradients throw on NaN).
    if (finite) {
      const glow = ctx.createRadialGradient(node.x, node.y, r * 0.4, node.x, node.y, r + 9)
      glow.addColorStop(0, st.ring)
      glow.addColorStop(1, 'rgba(0,0,0,0)')
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 9, 0, 2 * Math.PI)
      ctx.fillStyle = glow
      ctx.fill()
    }

    if (node.in_alert) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 4, 0, 2 * Math.PI)
      ctx.strokeStyle = 'rgba(255,45,79,0.6)'
      ctx.lineWidth = 1.6 / scale
      ctx.stroke()
    }

    ctx.beginPath()
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
    if (finite) {
      const g = ctx.createLinearGradient(node.x, node.y - r, node.x, node.y + r)
      g.addColorStop(0, '#ffffff')
      g.addColorStop(0.2, st.color)
      g.addColorStop(1, st.color)
      ctx.fillStyle = g
    } else {
      ctx.fillStyle = st.color
    }
    ctx.fill()
    ctx.lineWidth = (isHit ? 2.5 : node.in_alert ? 1.4 : 0.6) / scale
    ctx.strokeStyle = isHit ? '#fde047' : node.in_alert ? '#ff2d4f' : 'rgba(255,255,255,0.25)'
    ctx.stroke()

    if (showLabels && !dim) {
      const fsz = Math.max(10 / scale, 3)
      ctx.font = `600 ${fsz}px Inter, system-ui, sans-serif`
      ctx.fillStyle = '#e4e4e7'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      const lbl = node.label?.length > 18 ? node.label.slice(0, 18) + '…' : node.label
      ctx.fillText(lbl, node.x, node.y + r + 2)
    }
    ctx.globalAlpha = 1
  }, [showLabels])

  const linkColor = useCallback((l) => {
    const focusId = selRef.current?.id ?? hoverRef.current?.id ?? null
    const lit = litFor(focusId)
    if (lit) {
      return lit.has(idOf(l.source)) && lit.has(idOf(l.target))
        ? 'rgba(244,63,94,0.75)' : 'rgba(225,29,72,0.06)'
    }
    return 'rgba(225,29,72,0.25)'
  }, [])

  const runSearch = () => {
    const q = query.trim().toLowerCase()
    if (!q) return
    const hit = data.nodes.find((n) => n.label?.toLowerCase().includes(q))
    if (hit && Number.isFinite(hit.x)) {
      selRef.current = hit
      setSel(hit)
      fgRef.current?.centerAt(hit.x, hit.y, 600)
      fgRef.current?.zoom(2.4, 600)
    }
  }

  const exportPng = () => {
    const c = wrapRef.current?.querySelector('canvas')
    if (!c) return
    const a = document.createElement('a')
    a.download = 'entity-graph.png'
    a.href = c.toDataURL('image/png')
    a.click()
  }

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.()
    else wrapRef.current?.requestFullscreen?.()
  }

  if (!nodes.length) {
    return (
      <div className="text-center py-12 text-sm" style={{ color: 'var(--text-3)' }}>
        No entity relationships found for this alert's context.
      </div>
    )
  }

  const alertCount = nodes.filter((n) => n.in_alert).length

  return (
    <div className="space-y-3">
      <div
        ref={wrapRef}
        className="relative rounded-xl overflow-hidden"
        style={{ background: 'radial-gradient(ellipse at 50% 0%, #16070b 0%, var(--bg) 70%)', border: '1px solid var(--border-2)' }}
      >
        <div
          className="absolute top-2 left-2 z-10 text-[10px] font-mono px-2 py-1 rounded flex items-center gap-2"
          style={{ background: 'rgba(0,0,0,0.55)', color: 'var(--text-3)', border: '1px solid var(--border)' }}
        >
          <span>{nodes.length} entities · {edges.length} relationships</span>
          {alertCount > 0 && <span style={{ color: '#fb7185' }}>· {alertCount} in alert</span>}
        </div>

        <div className="absolute top-2 right-2 z-10 flex items-center gap-1.5">
          <div className="flex items-center rounded-md overflow-hidden mr-1"
            style={{ background: 'rgba(0,0,0,0.55)', border: '1px solid var(--border)' }}>
            <input
              value={query}
              onChange={(e) => { setQuery(e.target.value); queryRef.current = e.target.value.trim().toLowerCase() }}
              onKeyDown={(e) => e.key === 'Enter' && runSearch()}
              placeholder="Find entity…"
              className="bg-transparent text-[11px] px-2 py-1 w-28 outline-none"
              style={{ color: 'var(--text-1)' }}
            />
            <button onClick={runSearch} title="Search" className="px-1.5 self-stretch" style={{ color: 'var(--text-2)' }}>⏎</button>
          </div>
          <ToolBtn title="Zoom in" onClick={() => fgRef.current?.zoom((fgRef.current.zoom() || 1) * 1.4, 300)}>+</ToolBtn>
          <ToolBtn title="Zoom out" onClick={() => fgRef.current?.zoom((fgRef.current.zoom() || 1) / 1.4, 300)}>−</ToolBtn>
          <ToolBtn title="Fit to view" onClick={() => fgRef.current?.zoomToFit(500, 40)}>⤢</ToolBtn>
          <ToolBtn title={showLabels ? 'Hide labels' : 'Show labels'} active={showLabels} onClick={() => setShowLabels((v) => !v)}>A</ToolBtn>
          <ToolBtn title="Export PNG" onClick={exportPng}>⤓</ToolBtn>
          <ToolBtn title="Fullscreen" active={fs} onClick={toggleFullscreen}>⛶</ToolBtn>
        </div>

        <ForceGraph2D
          ref={fgRef}
          width={width}
          height={380}
          graphData={data}
          backgroundColor="rgba(0,0,0,0)"
          nodeRelSize={1}
          nodeLabel={(n) =>
            `<div style="font:12px Inter;color:#fff;background:#1a1014;border:1px solid #e11d48;padding:6px 8px;border-radius:6px">
               <b>${n.label}</b><br/>${(NODE_STYLE[n.type] || NODE_STYLE.unknown).label}
               ${n.event_count ? `<br/>${n.event_count} alert(s)` : ''}
               ${n.in_alert ? `<br/>⚠ ${n.alert_rules?.join(', ') || 'in alert'}` : ''}
             </div>`}
          nodeCanvasObject={paintNode}
          nodePointerAreaPaint={(node, color, ctx) => {
            ctx.fillStyle = color
            ctx.beginPath()
            ctx.arc(node.x, node.y, node.val + 4, 0, 2 * Math.PI)
            ctx.fill()
          }}
          linkColor={linkColor}
          linkWidth={(l) => Math.min(4, Math.sqrt(l.value))}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={(l) => (l.value > 3 ? 2 : 0)}
          linkDirectionalParticleColor={() => '#f43f5e'}
          linkDirectionalParticleWidth={2}
          onNodeHover={(n) => { hoverRef.current = n; if (wrapRef.current) wrapRef.current.style.cursor = n ? 'pointer' : 'default' }}
          onNodeClick={(n) => { selRef.current = n; setSel(n); fgRef.current?.centerAt(n.x, n.y, 500); fgRef.current?.zoom(2.2, 500) }}
          onBackgroundClick={() => { selRef.current = null; setSel(null) }}
          cooldownTicks={120}
        />
      </div>

      <div className="flex flex-wrap gap-3 text-[11px]" style={{ color: 'var(--text-4)' }}>
        {Object.entries(NODE_STYLE).filter(([k]) => k !== 'unknown').map(([k, v]) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: v.color, boxShadow: `0 0 6px ${v.color}` }} /> {v.label}
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: 'transparent', border: '1.5px solid #ff2d4f' }} /> in alert
        </span>
        <span className="ml-auto italic">Hover to isolate · click to focus</span>
      </div>

      {sel && (
        <div className="rounded-xl p-4" style={{ background: 'var(--surface)', border: '1px solid var(--border-2)' }}>
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-bold text-white font-mono">{sel.label}</p>
            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}>
              {(NODE_STYLE[sel.type] || NODE_STYLE.unknown).label}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div style={{ color: 'var(--text-3)' }}>Alerts involving</div>
            <div className="text-white font-bold">{sel.event_count || 0}</div>
            <div style={{ color: 'var(--text-3)' }}>Connections</div>
            <div className="text-white font-bold">{(adjacency[sel.id] || new Set()).size}</div>
            {sel.severity && (<>
              <div style={{ color: 'var(--text-3)' }}>Worst severity</div>
              <div className="font-bold" style={{ color: '#f87171' }}>{sel.severity}</div>
            </>)}
            {sel.risk_score != null && (<>
              <div style={{ color: 'var(--text-3)' }}>Risk score</div>
              <div className="text-white font-bold">{Number(sel.risk_score).toFixed(1)} / 10</div>
            </>)}
          </div>
          {sel.alert_rules?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {sel.alert_rules.map((r) => (
                <span key={r} className="text-[10px] px-2 py-0.5 rounded-full"
                  style={{ background: 'rgba(225,29,72,0.1)', color: '#f87171', border: '1px solid rgba(225,29,72,0.25)' }}>
                  {r}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
