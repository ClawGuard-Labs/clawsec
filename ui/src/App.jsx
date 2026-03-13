import { useState, useMemo } from 'react'
import './App.css'
import { useGraphSSE }   from './useGraphSSE'
import { AlertPanel }    from './AlertPanel'
import { SessionGrid }   from './SessionGrid'
import { GraphView }     from './GraphView'
import { Inspector }     from './Inspector'

// Filter nodes and edges to only those belonging to a specific session.
// File and network nodes that have no session_id are included if they are
// directly connected (via an edge) to a process in the session.
function filterBySession(nodes, edges, sessionId) {
  // Collect node IDs that belong to the session
  const sessionNodeIds = new Set(
    Object.values(nodes)
      .filter(n => n.session_id === sessionId)
      .map(n => n.id)
  )

  // Include nodes reachable via edges from session nodes
  for (const edge of Object.values(edges)) {
    if (sessionNodeIds.has(edge.src) && nodes[edge.dst]) sessionNodeIds.add(edge.dst)
    if (sessionNodeIds.has(edge.dst) && nodes[edge.src]) sessionNodeIds.add(edge.src)
  }

  const filteredNodes = {}
  for (const id of sessionNodeIds) {
    if (nodes[id]) filteredNodes[id] = nodes[id]
  }

  const filteredEdges = {}
  for (const [id, edge] of Object.entries(edges)) {
    if (sessionNodeIds.has(edge.src) && sessionNodeIds.has(edge.dst)) {
      filteredEdges[id] = edge
    }
  }

  return { filteredNodes, filteredEdges }
}

export default function App() {
  const { nodes, edges, alerts, status } = useGraphSSE()

  const [selectedNode,        setSelectedNode]        = useState(null)
  const [selectedAlert,       setSelectedAlert]       = useState(null)
  const [highlightedNodeIds,  setHighlightedNodeIds]  = useState([])
  const [selectedSession,     setSelectedSession]     = useState(null)  // null = grid view

  // ── Alert selection ────────────────────────────────────────────────────────
  function handleAlertSelect(alert) {
    setSelectedAlert(alert)
    setSelectedNode(null)
    setHighlightedNodeIds(alert?.node_ids ?? [])

    // Auto drill-down into the session that owns this alert
    if (alert?.session_id) {
      setSelectedSession(alert.session_id)
    }
  }

  // ── Node selection (inside drill-down graph) ──────────────────────────────
  function handleNodeSelect(nodeData) {
    setSelectedNode(nodeData)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }

  // ── Session card click → drill in ─────────────────────────────────────────
  function handleSessionSelect(sessionId) {
    setSelectedSession(sessionId)
    setSelectedNode(null)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }

  // ── Back button in graph view → return to grid ────────────────────────────
  function handleBack() {
    setSelectedSession(null)
    setSelectedNode(null)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }

  // ── Compute filtered graph for the selected session ────────────────────────
  const { filteredNodes, filteredEdges } = useMemo(() => {
    if (!selectedSession) return { filteredNodes: nodes, filteredEdges: edges }
    return filterBySession(nodes, edges, selectedSession)
  }, [nodes, edges, selectedSession])

  // Session ID to highlight (when an alert is selected but we're still in grid)
  const highlightedSessionId = selectedAlert?.session_id ?? null

  return (
    <div className="app">
      <div className="topbar">
        <span className="topbar-title">
          {selectedSession
            ? <>
                <span className="topbar-back" onClick={handleBack}>← Sessions</span>
                <span className="topbar-sep">·</span>
                {selectedSession}
              </>
            : 'ClawSec — Session Overview'
          }
        </span>
        <span className="status-pill">
          <span className={`dot ${status}`} />
          {status === 'connected'
            ? `live · ${Object.keys(nodes).length} nodes · ${alerts.length} alerts`
            : status}
        </span>
      </div>

      <div className="main-area">
        <AlertPanel
          alerts={alerts}
          selectedAlert={selectedAlert}
          onSelect={handleAlertSelect}
        />

        {selectedSession ? (
          // ── Drill-down: full Cytoscape graph for one session ──────────────
          <GraphView
            nodes={filteredNodes}
            edges={filteredEdges}
            highlightedNodeIds={highlightedNodeIds}
            onNodeSelect={handleNodeSelect}
            onBack={handleBack}
            sessionLabel={selectedSession}
          />
        ) : (
          // ── Grid view: PPT-style session cards ────────────────────────────
          <SessionGrid
            nodes={nodes}
            alerts={alerts}
            highlightedSessionId={highlightedSessionId}
            onSessionSelect={handleSessionSelect}
          />
        )}

        <Inspector
          node={selectedNode}
          alert={selectedAlert}
        />
      </div>
    </div>
  )
}
