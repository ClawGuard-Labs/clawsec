import { useState, useMemo, useCallback, lazy, Suspense } from 'react'
import './App.css'
import { useGraphSSE }   from './useGraphSSE'
import { AlertPanel }    from './AlertPanel'
import { AIServicesBar }  from './AIServicesBar'
import { SessionGrid, buildSessions } from './SessionGrid'
import { Inspector }     from './Inspector'

const GraphView = lazy(() => import('./GraphView').then(m => ({ default: m.GraphView })))
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
  const handleAlertSelect = useCallback((alert) => {
    setSelectedAlert(alert)
    setSelectedNode(null)
    setHighlightedNodeIds(alert?.node_ids ?? [])

    if (alert?.session_id) {
      setSelectedSession(alert.session_id)
    }
  }, [])

  // ── Node selection (inside drill-down graph) ──────────────────────────────
  const handleNodeSelect = useCallback((nodeData) => {
    setSelectedNode(nodeData)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }, [])

  // ── Session card click → drill in ─────────────────────────────────────────
  const handleSessionSelect = useCallback((sessionId) => {
    setSelectedSession(sessionId)
    setSelectedNode(null)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }, [])

  // ── Back button in graph view → return to grid ────────────────────────────
  const handleBack = useCallback(() => {
    setSelectedSession(null)
    setSelectedNode(null)
    setSelectedAlert(null)
    setHighlightedNodeIds([])
  }, [])

  // ── Compute filtered graph for the selected session ────────────────────────
  const { filteredNodes, filteredEdges } = useMemo(() => {
    if (!selectedSession) return { filteredNodes: nodes, filteredEdges: edges }
    return filterBySession(nodes, edges, selectedSession)
  }, [nodes, edges, selectedSession])

  // Session ID to highlight (when an alert is selected but we're still in grid)
  const highlightedSessionId = selectedAlert?.session_id ?? null

  const sessions = useMemo(
    () => buildSessions(nodes, alerts),
    [nodes, alerts]
  )
  const inspectorRootProc = useMemo(() => {
    if (!selectedNode?.session_id) return null
    return sessions.find(s => s.id === selectedNode.session_id)?.rootProc ?? null
  }, [sessions, selectedNode])

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
            : 'Onyx — Session Overview'
          }
        </span>
        <span className="status-pill">
          <span className={`dot ${status}`} />
          {status === 'connected'
            ? `live · ${Object.keys(nodes).length} nodes · ${alerts.length} alerts`
            : status}
        </span>
      </div>

      <AIServicesBar />

      <div className="main-area">
        <AlertPanel
          alerts={alerts}
          selectedAlert={selectedAlert}
          onSelect={handleAlertSelect}
        />

        {selectedSession ? (
          // ── Drill-down: full Cytoscape graph for one session ──────────────
          <Suspense fallback={<div className="graph-area"><div className="empty-state">Loading graph…</div></div>}>
            <GraphView
              nodes={filteredNodes}
              edges={filteredEdges}
              highlightedNodeIds={highlightedNodeIds}
              onNodeSelect={handleNodeSelect}
              onBack={handleBack}
            />
          </Suspense>
        ) : (
          <SessionGrid
            sessions={sessions}
            highlightedSessionId={highlightedSessionId}
            onSessionSelect={handleSessionSelect}
          />
        )}

        <Inspector
          node={selectedNode}
          alert={selectedAlert}
          rootProc={inspectorRootProc}
        />
      </div>
    </div>
  )
}
