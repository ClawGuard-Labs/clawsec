import React, { useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'

cytoscape.use(dagre)

// Simple debounce used for zoom/pan → canvas-resize throttling
function debounce(fn, ms) {
  let t
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms) }
}

// ── label helpers ─────────────────────────────────────────────────────────────

function shortPath(path) {
  if (!path) return ''
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  if (parts.length <= 2) return path
  return '…/' + parts.slice(-2).join('/')
}

function nodeLabel(n) {
  if (n.type === 'file')    return shortPath(n.label)
  if (n.type === 'network') return n.label
  return n.label + (n.meta?.pid ? `\n(${n.meta.pid})` : '')
}

// ── Cytoscape stylesheet ──────────────────────────────────────────────────────

const STYLE = [
  {
    selector: 'node',
    style: {
      label: 'data(shortLabel)',
      'font-size': '11px',
      'font-family': 'SF Mono, Fira Code, Consolas, monospace',
      color: '#e6edf3',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': '6px',
      'text-max-width': '140px',
      'text-overflow-wrap': 'anywhere',
      'text-wrap': 'wrap',
      'text-background-color': 'rgba(13,17,23,0.75)',
      'text-background-opacity': 1,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
    },
  },
  {
    selector: 'node[type="process"]',
    style: {
      shape: 'ellipse',
      width: '38px', height: '38px',
      'background-color': '#0d2040',
      'border-color': '#58a6ff', 'border-width': '1.5px',
    },
  },
  {
    selector: 'node[type="file"]',
    style: {
      shape: 'rectangle',
      width: '44px', height: '22px',
      'background-color': '#1a1f00',
      'border-color': '#b8953a', 'border-width': '1.5px',
    },
  },
  {
    selector: 'node[type="network"]',
    style: {
      shape: 'diamond',
      width: '36px', height: '36px',
      'background-color': '#220f00',
      'border-color': '#f0883e', 'border-width': '1.5px',
    },
  },
  {
    selector: 'node[?is_tainted]',
    style: {
      'border-color': '#e05252', 'border-width': '3px',
      'background-color': '#2a0808',
    },
  },
  {
    selector: 'node.alerted',
    style: {
      'border-color': '#f0e040', 'border-width': '4px',
      'background-color': '#2a2200',
      'shadow-blur': '12px', 'shadow-color': '#f0e040',
      'shadow-opacity': 0.8, 'shadow-offset-x': 0, 'shadow-offset-y': 0,
      'z-index': 20,
    },
  },
  {
    selector: 'node:selected',
    style: {
      'border-color': '#58a6ff', 'border-width': '3.5px',
      'background-color': '#0a2048', 'z-index': 10,
    },
  },
  {
    selector: 'edge',
    style: {
      width: 1.2,
      'line-color': '#30363d', 'target-arrow-color': '#30363d',
      'target-arrow-shape': 'triangle', 'arrow-scale': 0.8,
      'curve-style': 'bezier', opacity: 0.8,
    },
  },
  {
    selector: 'edge[type="spawned"]',
    style: { 'line-color': '#58a6ff', 'target-arrow-color': '#58a6ff', width: 1.8 },
  },
  {
    selector: 'edge[type="wrote"]',
    style: { 'line-color': '#d29922', 'target-arrow-color': '#d29922' },
  },
  {
    selector: 'edge[type="read"]',
    style: {
      'line-color': '#3a3a1a', 'target-arrow-color': '#3a3a1a',
      'line-style': 'dashed', 'line-dash-pattern': [4, 3],
    },
  },
  {
    selector: 'edge[type="connected"]',
    style: { 'line-color': '#f0883e', 'target-arrow-color': '#f0883e' },
  },
  {
    selector: 'edge[type="sourced"]',
    style: { 'line-color': '#e05252', 'target-arrow-color': '#e05252', width: 2 },
  },
  {
    selector: 'edge[?tainted]',
    style: { 'line-color': '#882020', 'target-arrow-color': '#882020', width: 2, opacity: 1 },
  },
  {
    selector: 'edge:selected',
    style: { 'line-color': '#58a6ff', 'target-arrow-color': '#58a6ff', width: 2.5 },
  },
]

// ── Layout ────────────────────────────────────────────────────────────────────

const LAYOUT_BASE = {
  name: 'dagre',
  rankDir: 'LR',
  align: 'UL',
  ranker: 'network-simplex',
  nodeSep: 40,
  rankSep: 100,
  edgeSep: 10,
  padding: 50,
  animate: true,
  animationDuration: 300,
  fit: false,   // never auto-fit — zoom is controlled explicitly
}

// ── Smooth zoom helper ────────────────────────────────────────────────────────

function smoothZoom(cy, factor) {
  const newZoom = Math.min(Math.max(cy.zoom() * factor, cy.minZoom()), cy.maxZoom())
  const renderedPos = { x: cy.width() / 2, y: cy.height() / 2 }
  cy.animate(
    { zoom: { level: newZoom, renderedPosition: renderedPos } },
    { duration: 220, easing: 'ease-in-out-quad' }
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export function GraphView({ nodes, edges, highlightedNodeIds, onNodeSelect, onBack }) {
  const containerRef  = useRef(null)
  const cyRef         = useRef(null)
  const pendingLayout = useRef(false)
  const hasInitialFit = useRef(false)

  // ── Canvas resize ─────────────────────────────────────────────────────────
  // After each layout or zoom/pan event, expand the DOM container to match the
  // actual rendered graph bounds so the scroll-wrapper's scrollbars cover the
  // full graph.  Uses refs so this never triggers a React re-render.
  const syncCanvasSize = useCallback(() => {
    const cy        = cyRef.current
    const container = containerRef.current
    if (!cy || !container) return
    const eles = cy.elements()
    if (eles.length === 0) return

    const PAD     = 80
    const wrapper = container.parentElement   // .graph-scroll-wrapper
    if (!wrapper) return

    // Bounding box in screen (rendered) px, relative to the canvas top-left
    const bb   = eles.renderedBoundingBox({ includeLabels: true })
    const newW = Math.max(wrapper.clientWidth,  Math.ceil(bb.x2) + PAD)
    const newH = Math.max(wrapper.clientHeight, Math.ceil(bb.y2) + PAD)

    container.style.width  = newW + 'px'
    container.style.height = newH + 'px'
    cy.resize()   // tell Cytoscape the canvas grew (preserves zoom/pan)
  }, [])

  // Initialise Cytoscape once
  useEffect(() => {
    if (!containerRef.current) return

    cyRef.current = cytoscape({
      container: containerRef.current,
      style: STYLE,
      elements: [],
      wheelSensitivity: 0.15,
      minZoom: 0.25,   // prevent nodes from shrinking too small
      maxZoom: 5,
    })

    const cy      = cyRef.current
    const container = containerRef.current

    cy.on('tap', 'node', (e) => {
      onNodeSelect && onNodeSelect(e.target.data())
    })
    cy.on('tap', (e) => {
      if (e.target === cy) onNodeSelect && onNodeSelect(null)
    })

    cy.on('mouseover', 'edge', (e) => {
      const edge = e.target
      edge.style({
        label: edge.data('type'), 'font-size': '9px', color: '#8b949e',
        'text-background-color': '#0d1117', 'text-background-opacity': 1,
        'text-background-padding': '2px',
      })
    })
    cy.on('mouseout', 'edge', (e) => {
      e.target.removeStyle('label font-size color text-background-color text-background-opacity text-background-padding')
    })

    // ── Box-zoom: drag on empty space to zoom into that area ──────────────
    //
    // Strategy: intercept mousedown in the CAPTURE phase before Cytoscape
    // sees it. Hit-test every node's rendered bounding box. If the click
    // lands on empty space, stop the event (Cytoscape never pans) and run
    // the box-zoom. If it lands on a node, do nothing — Cytoscape handles
    // select/drag as normal.

    const bz = { active: false, startX: 0, startY: 0, el: null }

    function hitTestNodes(x, y) {
      // Returns true if (x, y) in screen-px is inside any node's rendered box.
      return cy.nodes().some(node => {
        const bb = node.renderedBoundingBox({ includeLabels: false })
        return x >= bb.x1 && x <= bb.x2 && y >= bb.y1 && y <= bb.y2
      })
    }

    function onMouseDown(e) {
      if (e.button !== 0) return

      const rect = container.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      // If the click is on a node, let Cytoscape handle it normally.
      if (hitTestNodes(x, y)) return

      // Empty space — take ownership of this drag for box-zoom.
      e.stopImmediatePropagation()

      bz.active = true
      bz.startX = x
      bz.startY = y

      bz.el = document.createElement('div')
      bz.el.className = 'box-zoom-rect'
      container.appendChild(bz.el)
    }

    function onMouseMove(e) {
      if (!bz.active || !bz.el) return
      const rect = container.getBoundingClientRect()
      const cx  = e.clientX - rect.left
      const cy2 = e.clientY - rect.top
      bz.el.style.left   = Math.min(cx, bz.startX) + 'px'
      bz.el.style.top    = Math.min(cy2, bz.startY) + 'px'
      bz.el.style.width  = Math.abs(cx - bz.startX) + 'px'
      bz.el.style.height = Math.abs(cy2 - bz.startY) + 'px'
    }

    function onMouseUp(e) {
      if (!bz.active) return
      bz.active = false

      if (bz.el) { bz.el.remove(); bz.el = null }

      const rect = container.getBoundingClientRect()
      const endX = e.clientX - rect.left
      const endY = e.clientY - rect.top

      const x1 = Math.min(endX, bz.startX)
      const y1 = Math.min(endY, bz.startY)
      const x2 = Math.max(endX, bz.startX)
      const y2 = Math.max(endY, bz.startY)

      if (x2 - x1 < 10 || y2 - y1 < 10) return  // too small — treat as click

      // Convert screen rectangle → model space → animate zoom+pan to fit it.
      const pan  = cy.pan()
      const zoom = cy.zoom()
      const mx1 = (x1 - pan.x) / zoom,  my1 = (y1 - pan.y) / zoom
      const mx2 = (x2 - pan.x) / zoom,  my2 = (y2 - pan.y) / zoom

      const vw = cy.width(),  vh = cy.height()
      const newZoom = Math.min(
        vw / (mx2 - mx1) * 0.88,
        vh / (my2 - my1) * 0.88,
        cy.maxZoom()
      )
      const newPan = {
        x: vw / 2 - newZoom * (mx1 + mx2) / 2,
        y: vh / 2 - newZoom * (my1 + my2) / 2,
      }
      cy.animate({ zoom: newZoom, pan: newPan }, { duration: 300, easing: 'ease-in-out-quad' })
    }

    // capture: true so we get the event before Cytoscape's bubble-phase listeners
    container.addEventListener('mousedown', onMouseDown, { capture: true })
    container.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)

    // Resize canvas whenever the user zooms or pans so scrollbars stay accurate
    cy.on('zoom pan', debounce(syncCanvasSize, 120))

    return () => {
      container.removeEventListener('mousedown', onMouseDown, { capture: true })
      container.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
      cy.destroy()
      hasInitialFit.current = false
    }
  }, [syncCanvasSize]) // eslint-disable-line react-hooks/exhaustive-deps

  // Sync nodes & edges into Cytoscape
  const syncGraph = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return

    const existingNodes = new Set(cy.nodes().map(n => n.id()))
    const existingEdges = new Set(cy.edges().map(e => e.id()))
    const toAdd = []

    for (const [id, n] of Object.entries(nodes)) {
      if (!existingNodes.has(id)) {
        toAdd.push({ group: 'nodes', data: { ...n, shortLabel: nodeLabel(n) } })
      } else {
        cy.getElementById(id).data({
          is_tainted: n.is_tainted,
          risk_score: n.risk_score,
          tags: n.tags,
          last_seen: n.last_seen,
          meta: n.meta,
        })
      }
    }

    for (const [id, e] of Object.entries(edges)) {
      if (!existingEdges.has(id)) {
        toAdd.push({
          group: 'edges',
          data: { id: e.id, source: e.src, target: e.dst, type: e.type, tainted: e.tainted },
        })
      }
    }

    if (toAdd.length > 0) {
      cy.add(toAdd)
      pendingLayout.current = true
    }

    if (pendingLayout.current) {
      pendingLayout.current = false
      if (!hasInitialFit.current) {
        hasInitialFit.current = true
        const layout = cy.layout(LAYOUT_BASE)
        layout.on('layoutstop', () => {
          cy.animate(
            { fit: { eles: cy.elements(), padding: 50 } },
            { duration: 250, complete: syncCanvasSize },
          )
        })
        layout.run()
      } else {
        const layout = cy.layout(LAYOUT_BASE)
        layout.on('layoutstop', syncCanvasSize)
        layout.run()
      }
    }
  }, [nodes, edges, syncCanvasSize])

  useEffect(() => { syncGraph() }, [syncGraph])

  // Highlight nodes linked to the selected alert
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.nodes().removeClass('alerted')
    if (!highlightedNodeIds?.length) return
    const targets = cy.nodes().filter(n => highlightedNodeIds.includes(n.id()))
    if (targets.length === 0) return
    targets.addClass('alerted')
    cy.animate({ fit: { eles: targets, padding: 100 } }, { duration: 400, easing: 'ease-in-out-quad' })
  }, [highlightedNodeIds])

  // ── Zoom controls ──────────────────────────────────────────────────────────
  function zoomIn()  { if (cyRef.current) smoothZoom(cyRef.current, 1.35) }
  function zoomOut() { if (cyRef.current) smoothZoom(cyRef.current, 0.75) }
  function fitAll()  {
    cyRef.current?.animate(
      { fit: { eles: cyRef.current.elements(), padding: 40 } },
      { duration: 300 }
    )
  }

  const nodeCount = Object.keys(nodes).length

  return (
    <div className="graph-area">
      <div className="graph-scroll-wrapper">
        <div className="cyto-container" ref={containerRef} />
      </div>

      {onBack && (
        <button className="graph-back-btn" onClick={onBack}>
          ← All Sessions
        </button>
      )}

      <div className="graph-toolbar">
        <button className="graph-btn" onClick={zoomIn}  title="Zoom in">+</button>
        <button className="graph-btn" onClick={zoomOut} title="Zoom out">−</button>
        <button className="graph-btn" onClick={fitAll}  title="Fit all">⊡</button>
      </div>

      <div className="graph-legend">
        <span className="legend-item"><span className="legend-dot proc"   />Process</span>
        <span className="legend-item"><span className="legend-dot file"   />Model file</span>
        <span className="legend-item"><span className="legend-dot net"    />Network</span>
        <span className="legend-item"><span className="legend-dot taint"  />Tainted</span>
        <span className="legend-item"><span className="legend-dot alerted"/>Alert</span>
      </div>

      {nodeCount === 0 && (
        <div className="graph-hint">
          No tainted activity detected yet.<br />
          Only model-file downloads and tainted process chains appear here.
        </div>
      )}
    </div>
  )
}
