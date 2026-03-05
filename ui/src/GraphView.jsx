import React, { useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'

cytoscape.use(dagre)

// ── label helpers ─────────────────────────────────────────────────────────────

/** Shorten a file path to its last 2 components, prefixed with "…/" */
function shortPath(path) {
  if (!path) return ''
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  if (parts.length <= 2) return path
  return '…/' + parts.slice(-2).join('/')
}

/** Return a display label for any node */
function nodeLabel(n) {
  if (n.type === 'file')    return shortPath(n.label)
  if (n.type === 'network') return n.label   // already short: IP:port
  // process — comm is already short; add pid for disambiguation
  return n.label + (n.meta?.pid ? `\n(${n.meta.pid})` : '')
}

// ── Cytoscape stylesheet ──────────────────────────────────────────────────────

const STYLE = [
  // shared node defaults
  {
    selector: 'node',
    style: {
      label: 'data(shortLabel)',
      'font-size': '9px',
      'font-family': 'SF Mono, Fira Code, Consolas, monospace',
      color: '#c9d1d9',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': '4px',
      'text-max-width': '100px',
      'text-overflow-wrap': 'ellipsis',
      'text-wrap': 'ellipsis',
    },
  },
  // process — circle
  {
    selector: 'node[type="process"]',
    style: {
      shape: 'ellipse',
      width: '38px',
      height: '38px',
      'background-color': '#0d2040',
      'border-color': '#58a6ff',
      'border-width': '1.5px',
    },
  },
  // file — rectangle
  {
    selector: 'node[type="file"]',
    style: {
      shape: 'rectangle',
      width: '44px',
      height: '22px',
      'background-color': '#1a1f00',
      'border-color': '#b8953a',
      'border-width': '1.5px',
    },
  },
  // network — diamond
  {
    selector: 'node[type="network"]',
    style: {
      shape: 'diamond',
      width: '36px',
      height: '36px',
      'background-color': '#220f00',
      'border-color': '#f0883e',
      'border-width': '1.5px',
    },
  },
  // tainted highlight — red border + darker bg
  {
    selector: 'node[?is_tainted]',
    style: {
      'border-color': '#e05252',
      'border-width': '3px',
      'background-color': '#2a0808',
    },
  },
  // selected node
  {
    selector: 'node:selected',
    style: {
      'border-color': '#58a6ff',
      'border-width': '3.5px',
      'background-color': '#0a2048',
      'z-index': 10,
    },
  },
  // edges — no text labels; color encodes meaning
  {
    selector: 'edge',
    style: {
      width: 1.2,
      'line-color': '#30363d',
      'target-arrow-color': '#30363d',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.8,
      'curve-style': 'bezier',
      opacity: 0.8,
    },
  },
  // spawned (process→process)
  {
    selector: 'edge[type="spawned"]',
    style: {
      'line-color': '#58a6ff',
      'target-arrow-color': '#58a6ff',
      width: 1.8,
    },
  },
  // wrote / read (process→file)
  {
    selector: 'edge[type="wrote"]',
    style: {
      'line-color': '#d29922',
      'target-arrow-color': '#d29922',
      'line-style': 'solid',
    },
  },
  {
    selector: 'edge[type="read"]',
    style: {
      'line-color': '#3a3a1a',
      'target-arrow-color': '#3a3a1a',
      'line-style': 'dashed',
      'line-dash-pattern': [4, 3],
    },
  },
  // connected (process→network)
  {
    selector: 'edge[type="connected"]',
    style: {
      'line-color': '#f0883e',
      'target-arrow-color': '#f0883e',
    },
  },
  // sourced (network→file: download)
  {
    selector: 'edge[type="sourced"]',
    style: {
      'line-color': '#e05252',
      'target-arrow-color': '#e05252',
      width: 2,
    },
  },
  // tainted edges
  {
    selector: 'edge[?tainted]',
    style: {
      'line-color': '#882020',
      'target-arrow-color': '#882020',
      width: 2,
      opacity: 1,
    },
  },
  // edge tooltip on hover (shown via title data)
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#58a6ff',
      'target-arrow-color': '#58a6ff',
      width: 2.5,
    },
  },
]

// ── Layout ────────────────────────────────────────────────────────────────────

const LAYOUT = {
  name: 'dagre',
  rankDir: 'LR',      // left-to-right: net→proc→file
  align: 'UL',
  ranker: 'network-simplex',
  nodeSep: 40,        // horizontal gap between nodes in the same rank
  rankSep: 100,       // vertical gap between ranks
  edgeSep: 10,
  padding: 50,
  animate: true,
  animationDuration: 400,
  fit: true,
}

// ── Component ─────────────────────────────────────────────────────────────────

export function GraphView({ nodes, edges, onNodeSelect }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  // track whether we need to re-run the layout (only when new elements added)
  const pendingLayout = useRef(false)

  // Initialise Cytoscape once
  useEffect(() => {
    if (!containerRef.current) return

    cyRef.current = cytoscape({
      container: containerRef.current,
      style: STYLE,
      elements: [],
      wheelSensitivity: 0.25,
      minZoom: 0.05,
      maxZoom: 5,
    })

    const cy = cyRef.current

    cy.on('tap', 'node', (e) => {
      onNodeSelect && onNodeSelect(e.target.data())
    })
    cy.on('tap', (e) => {
      if (e.target === cy) onNodeSelect && onNodeSelect(null)
    })

    // Show edge type label as a tooltip-style overlay on hover
    cy.on('mouseover', 'edge', (e) => {
      const edge = e.target
      edge.style({ label: edge.data('type'), 'font-size': '9px', color: '#8b949e',
        'text-background-color': '#0d1117', 'text-background-opacity': 1,
        'text-background-padding': '2px' })
    })
    cy.on('mouseout', 'edge', (e) => {
      e.target.removeStyle('label font-size color text-background-color text-background-opacity text-background-padding')
    })

    return () => { cy.destroy() }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Sync nodes & edges
  const syncGraph = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return

    const existingNodes = new Set(cy.nodes().map(n => n.id()))
    const existingEdges = new Set(cy.edges().map(e => e.id()))

    const toAdd = []

    for (const [id, n] of Object.entries(nodes)) {
      if (!existingNodes.has(id)) {
        toAdd.push({
          group: 'nodes',
          data: { ...n, shortLabel: nodeLabel(n) },
        })
      } else {
        // Update taint / risk on existing node
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
          data: {
            id: e.id,
            source: e.src,
            target: e.dst,
            type: e.type,
            tainted: e.tainted,
          },
        })
      }
    }

    if (toAdd.length > 0) {
      cy.add(toAdd)
      pendingLayout.current = true
    }

    // Debounce layout so rapid-fire events don't thrash
    if (pendingLayout.current) {
      pendingLayout.current = false
      cy.layout(LAYOUT).run()
    }
  }, [nodes, edges])

  useEffect(() => { syncGraph() }, [syncGraph])

  // ── Zoom controls ──────────────────────────────────────────────────────────
  function zoomIn()  { cyRef.current?.zoom(cyRef.current.zoom() * 1.3) }
  function zoomOut() { cyRef.current?.zoom(cyRef.current.zoom() * 0.77) }
  function fitAll()  { cyRef.current?.fit(undefined, 40) }

  const nodeCount = Object.keys(nodes).length

  return (
    <div className="graph-area">
      <div className="cyto-container" ref={containerRef} />

      {/* Zoom / fit toolbar */}
      <div className="graph-toolbar">
        <button className="graph-btn" onClick={zoomIn}  title="Zoom in">+</button>
        <button className="graph-btn" onClick={zoomOut} title="Zoom out">−</button>
        <button className="graph-btn" onClick={fitAll}  title="Fit all">⊡</button>
      </div>

      {/* Legend */}
      <div className="graph-legend">
        <span className="legend-item"><span className="legend-dot proc" />Process</span>
        <span className="legend-item"><span className="legend-dot file" />Model file</span>
        <span className="legend-item"><span className="legend-dot net"  />Network</span>
        <span className="legend-item"><span className="legend-dot taint"/>Tainted</span>
      </div>

      {nodeCount === 0 && (
        <div className="graph-hint">
          No tainted activity detected yet.<br/>
          Only model-file downloads and tainted process chains appear here.
        </div>
      )}
    </div>
  )
}
